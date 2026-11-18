//! The text the engine aborted with (`Sys_Error`), pulled out of the crashing
//! thread's stack.
//!
//! Ported from the PHP `/error` endpoint, which only handled 32-bit x86 and
//! re-parsed the whole dump on every request. The idea is the same: when the
//! top frame is `Sys_Error`, the formatted message sits in a buffer on the
//! stack, and one of the registers points into it. A register that points
//! between the stack pointer and the frame pointer is taken to be that
//! pointer. It is a heuristic (the legacy one), so the result is only shown
//! where the crash page can show it to people who may manage the crash.

use minidump::{
    Minidump, MinidumpMiscInfo, MinidumpRawContext, MinidumpSystemInfo, MinidumpThreadList,
};
use minidump_processor::ProcessState;

const MAX_LEN: usize = 256;
const MIN_LEN: usize = 3;
/// More than this share of unprintable bytes means we are looking at data, not text.
const MAX_JUNK_PERCENT: usize = 20;

/// `engine.so!Sys_Error(...)` or `engine_srv.so!Sys_Error_Internal(...)`.
/// Symbols without parameters (PUBLIC records) count too.
pub fn is_sys_error_frame(module: &str, function: &str) -> bool {
    let module = module.to_ascii_lowercase();
    if module != "engine.so" && module != "engine_srv.so" {
        return false;
    }
    let rest = function
        .strip_prefix("Sys_Error_Internal")
        .or_else(|| function.strip_prefix("Sys_Error"));
    matches!(rest, Some(r) if r.is_empty() || r.starts_with('('))
}

/// A NUL-terminated string at `addr`, if that address lies inside the stack
/// bytes and the bytes look like text. Anything unprintable becomes `?`.
fn read_c_string(stack_base: u64, stack: &[u8], addr: u64) -> Option<String> {
    let start = usize::try_from(addr.checked_sub(stack_base)?).ok()?;
    let tail = stack.get(start..)?;
    let window = &tail[..tail.len().min(MAX_LEN)];
    let end = window.iter().position(|&b| b == 0).unwrap_or(window.len());

    let mut raw = &window[..end];
    while let [rest @ .., b'\n' | b'\r' | b' '] = raw {
        raw = rest;
    }
    if raw.len() < MIN_LEN {
        return None;
    }

    let junk = raw.iter().filter(|&&b| !(0x20..0x7f).contains(&b)).count();
    if junk * 100 > raw.len() * MAX_JUNK_PERCENT {
        return None;
    }
    Some(
        raw.iter()
            .map(|&b| {
                if (0x20..0x7f).contains(&b) {
                    char::from(b)
                } else {
                    '?'
                }
            })
            .collect(),
    )
}

/// The first register in `low..=high` (in the given order) that points at
/// something that reads like a message inside the stack.
pub fn find_error_string(
    registers: &[u64],
    low: u64,
    high: u64,
    stack_base: u64,
    stack: &[u8],
) -> Option<String> {
    registers
        .iter()
        .copied()
        .filter(|r| (low..=high).contains(r))
        .find_map(|r| read_c_string(stack_base, stack, r))
}

/// Read the registers and stack of the crashing thread (`thread`, an index into
/// `state.threads`) from the dump and look for the message.
pub fn extract<'a>(
    dump: &'a Minidump<'a, Vec<u8>>,
    state: &ProcessState,
    thread: usize,
) -> Option<String> {
    let thread_id = state.threads.get(thread)?.thread_id;
    let threads: MinidumpThreadList = dump.get_stream().ok()?;
    let system: MinidumpSystemInfo = dump.get_stream().ok()?;
    let misc: Option<MinidumpMiscInfo> = dump.get_stream().ok();
    let memory = dump.get_memory()?;

    let thread = threads.get_thread(thread_id)?;
    let context = thread.context(&system, misc.as_ref())?;
    let stack = thread.stack_memory(&memory)?;
    let (base, bytes) = (stack.base_address(), stack.bytes());
    let end = base.saturating_add(bytes.len() as u64);

    let (registers, low, high) = match &context.raw {
        MinidumpRawContext::X86(c) => {
            let (sp, bp) = (u64::from(c.esp), u64::from(c.ebp));
            let registers = [c.edi, c.esi, c.ebx, c.edx, c.ecx, c.eax].map(u64::from);
            // Legacy rule: between the stack and frame pointer. Without a usable
            // frame pointer, anywhere above the stack pointer.
            (registers.to_vec(), sp, if bp >= sp { bp } else { end })
        }
        // No frame pointer to rely on; argument registers first.
        MinidumpRawContext::Amd64(c) => (
            vec![c.rdi, c.rsi, c.rdx, c.rcx, c.r8, c.r9, c.rax, c.rbx],
            c.rsp,
            end,
        ),
        _ => return None,
    };
    find_error_string(&registers, low, high, base, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0x1000;

    fn stack(parts: &[(usize, &[u8])]) -> Vec<u8> {
        let mut s = vec![0u8; 512];
        for (offset, bytes) in parts {
            s[*offset..*offset + bytes.len()].copy_from_slice(bytes);
        }
        s
    }

    #[test]
    fn recognises_the_engine_abort_frames() {
        for (m, f, expected) in [
            (
                "engine_srv.so",
                "Sys_Error_Internal(bool, char const*, char*)",
                true,
            ),
            ("engine.so", "Sys_Error(char const*, ...)", true),
            ("ENGINE.SO", "Sys_Error", true),
            ("engine_srv.so", "Sys_Error_Internal", true),
            ("engine_srv.so", "Sys_ErrorMessage(char const*)", false),
            ("engine_srv.so", "Sys_Errors()", false),
            ("server_srv.so", "Sys_Error(char const*)", false),
            ("engine.dll", "Sys_Error(char const*)", false),
            ("", "", false),
        ] {
            assert_eq!(is_sys_error_frame(m, f), expected, "{m}!{f}");
        }
    }

    #[test]
    fn finds_the_message_a_register_points_at() {
        let s = stack(&[(0x40, b"Host_Error: bad map name\n\0")]);
        // The first register is outside the stack range, the second points at the text.
        let got = find_error_string(&[0, BASE + 0x40], BASE, BASE + 0x100, BASE, &s);
        assert_eq!(got.as_deref(), Some("Host_Error: bad map name"));
    }

    #[test]
    fn registers_outside_the_frame_are_ignored() {
        let s = stack(&[(0x40, b"some message\0")]);
        assert_eq!(
            find_error_string(&[BASE + 0x40], BASE + 0x80, BASE + 0x100, BASE, &s),
            None
        );
        assert_eq!(
            find_error_string(&[BASE + 0x40], BASE, BASE + 0x3f, BASE, &s),
            None
        );
        // Inside the range but past the end of the captured stack.
        assert_eq!(
            find_error_string(&[BASE + 0x9000], BASE, u64::MAX, BASE, &s),
            None
        );
        // Below the stack base must not underflow.
        assert_eq!(find_error_string(&[1], 0, u64::MAX, BASE, &s), None);
    }

    #[test]
    fn binary_data_and_empty_strings_are_skipped_in_favour_of_the_next_register() {
        let s = stack(&[
            (0x10, &[0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04, 0]),
            (0x30, b"real text here\0"),
        ]);
        // 0x00 reads as an empty string, 0x10 as junk.
        let got = find_error_string(
            &[BASE, BASE + 0x10, BASE + 0x30],
            BASE,
            BASE + 0x100,
            BASE,
            &s,
        );
        assert_eq!(got.as_deref(), Some("real text here"));
    }

    #[test]
    fn odd_bytes_become_question_marks_and_long_strings_are_cut() {
        let s = stack(&[(0x10, b"caf\xc3\xa9 is not on the menu\0")]);
        let got = find_error_string(&[BASE + 0x10], BASE, BASE + 0x100, BASE, &s).unwrap();
        assert_eq!(got, "caf?? is not on the menu");

        let long = vec![b'x'; 400];
        let s = stack(&[(0, &long[..400.min(long.len())])]);
        let got = find_error_string(&[BASE], BASE, BASE + 0x100, BASE, &s).unwrap();
        assert_eq!(got.len(), MAX_LEN);
    }

    #[test]
    fn a_string_running_off_the_captured_stack_is_still_read() {
        // No terminator before the end of the bytes.
        let s = b"abcdefgh".to_vec();
        assert_eq!(
            find_error_string(&[BASE + 2], BASE, BASE + 8, BASE, &s).as_deref(),
            Some("cdefgh")
        );
    }
}

/// `extract` end to end, on dumps built with minidump-synth. Its own context
/// helpers zero every register, so these build the contexts by hand.
#[cfg(test)]
mod synth_tests {
    use super::extract;
    use minidump::Minidump;
    use minidump_synth::{Memory, SynthMinidump, SystemInfo, Thread};
    use minidump_unwind::{Symbolizer, simple_symbol_supplier};
    use test_assembler::{Endian, Section};

    const BASE: u32 = 0x1000;
    const MESSAGE: &[u8] = b"Host_Error: Couldn't open maps/missing.bsp\n\0";
    const EXPECTED: &str = "Host_Error: Couldn't open maps/missing.bsp";
    const AMD64: u16 = 9;

    /// 0x1000..0x1240; the message is at BASE + 0x40.
    fn stack() -> Memory {
        let section = Section::with_endian(Endian::Little)
            .append_repeated(0, 0x40)
            .append_bytes(MESSAGE)
            .append_repeated(0, 0x200);
        Memory::with_section(section, u64::from(BASE))
    }

    /// CONTEXT_X86 with the given registers (all others zero).
    fn x86(edi: u32, ecx: u32, ebp: u32, esp: u32) -> Section {
        let section = Section::with_endian(Endian::Little)
            .D32(0x1003f) // context_flags
            .append_repeated(0, 4 * 6) // dr0-3, dr6, dr7
            .append_repeated(0, 112) // float_save
            .append_repeated(0, 4 * 4) // gs, fs, es, ds
            .D32(edi)
            .D32(0) // esi
            .D32(0) // ebx
            .D32(0) // edx
            .D32(ecx)
            .D32(0) // eax
            .D32(ebp)
            .D32(0x2000) // eip
            .D32(0) // cs
            .D32(0) // eflags
            .D32(esp)
            .D32(0) // ss
            .append_repeated(0, 512);
        assert_eq!(section.size(), 716);
        section
    }

    /// CONTEXT_AMD64 with the given registers (all others zero).
    fn amd64(rdi: u64, rsp: u64) -> Section {
        let section = Section::with_endian(Endian::Little)
            .append_repeated(0, 8 * 6) // p1-p6 home
            .D32(0x10001f) // context_flags
            .D32(0) // mx_csr
            .append_repeated(0, 2 * 6) // segment registers
            .D32(0) // eflags
            .append_repeated(0, 8 * 6) // dr0-3, dr6, dr7
            .append_repeated(0, 8 * 4) // rax, rcx, rdx, rbx
            .D64(rsp)
            .D64(0) // rbp
            .D64(0) // rsi
            .D64(rdi)
            .append_repeated(0, 8 * 8) // r8-r15
            .D64(0x2000) // rip
            .append_repeated(0, 512) // float_save
            .append_repeated(0, 16 * 26) // vector registers
            .append_repeated(0, 8 * 6);
        assert_eq!(section.size(), 1232);
        section
    }

    async fn run(system_info: SystemInfo, context: Section) -> Option<String> {
        let stack = stack();
        let thread = Thread::new(Endian::Little, 0x1234, &stack, &context);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_thread(thread)
            .add_system_info(system_info)
            .add(context)
            .add_memory(stack);
        let dump = Minidump::read(dump.finish().unwrap()).unwrap();
        let state = minidump_processor::process_minidump(
            &dump,
            &Symbolizer::new(simple_symbol_supplier(vec![])),
        )
        .await
        .unwrap();
        extract(&dump, &state, 0)
    }

    fn system(arch: Option<u16>) -> SystemInfo {
        let mut info = SystemInfo::new(Endian::Little);
        if let Some(arch) = arch {
            info.processor_architecture = arch;
        }
        info
    }

    #[tokio::test]
    async fn x86_register_inside_the_frame_points_at_the_message() {
        let (esp, ebp, ecx) = (BASE + 0x10, BASE + 0x100, BASE + 0x40);
        // edi comes first but is not a stack address; ecx is.
        assert_eq!(
            run(system(None), x86(0xdead_beef, ecx, ebp, esp))
                .await
                .as_deref(),
            Some(EXPECTED)
        );
    }

    #[tokio::test]
    async fn x86_pointer_outside_the_frame_is_not_trusted() {
        // The text is at +0x40 but the frame only spans +0x80..+0x100.
        let got = run(system(None), x86(0, BASE + 0x40, BASE + 0x100, BASE + 0x80)).await;
        assert_eq!(got, None);
    }

    #[tokio::test]
    async fn amd64_uses_the_argument_register() {
        let got = run(
            system(Some(AMD64)),
            amd64(u64::from(BASE) + 0x40, u64::from(BASE) + 0x10),
        )
        .await;
        assert_eq!(got.as_deref(), Some(EXPECTED));
    }
}
