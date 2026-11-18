//! Minidump -> the rows we store, via rust-minidump. The output shape follows
//! what the PHP version stored from `minidump_stackwalk -m`.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context;
use breakpad_symbols::{Module, breakpad_sym_lookup};
use minidump::{Minidump, MinidumpModule, MinidumpRawContext, MinidumpThreadList};
use minidump_processor::ProcessState;
use minidump_unwind::{CallStack, FrameTrust, StackFrame, SymbolProvider, Symbolizer, walk_stack};

use super::render::{self, FrameParts};
use super::repo;
use super::supplier::{RepoMap, StoreSupplier, SymbolStores};

/// A runaway recursion can have hundreds of thousands of frames.
const MAX_FRAMES_PER_THREAD: usize = 2048;
/// Frames that feed the stack hash.
const HASH_FRAMES: i64 = 10;

#[derive(Debug)]
pub struct ModuleRow {
    /// Debug file (`engine_srv.so`, `server.pdb`).
    pub name: String,
    /// Breakpad build id (upper-case GUID + age).
    pub identifier: String,
    /// `0x...`
    pub base: String,
    /// Symbols were available in a store.
    pub present: bool,
}

#[derive(Debug)]
pub struct FrameRow {
    pub thread: i64,
    pub frame: i64,
    pub module: String,
    pub function: String,
    pub file: String,
    pub line: i64,
    /// `0x...`
    pub offset: String,
    pub rendered: String,
    pub url: Option<String>,
}

#[derive(Debug)]
pub struct Analysis {
    /// The thread shown by default: the one that crashed, else thread 0.
    pub thread: i64,
    pub modules: Vec<ModuleRow>,
    /// Frames of `thread` and of thread 0 only (as in the PHP version).
    pub frames: Vec<FrameRow>,
    pub crash_module: Option<String>,
    pub crash_function: Option<String>,
    pub stackhash: Option<String>,
    /// The message of an engine `Sys_Error` abort, when that is what crashed.
    pub sys_error: Option<String>,
    /// What the dump says happened (`SIGSEGV / SEGV_MAPERR`) and where (`0x2800001`).
    pub crash_reason: Option<String>,
    pub crash_address: Option<String>,
    /// The instruction pointer was not code: the frames after the first one were
    /// unwound from the return address on the stack (see `bad_jump_frames`).
    pub bad_jump: bool,
}

pub async fn analyze(path: &Path, stores: &SymbolStores) -> anyhow::Result<Analysis> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    let dump = Minidump::read(bytes).context("not a valid minidump")?;

    let repos = RepoMap::default();
    let symbolizer = Symbolizer::new(StoreSupplier::new(stores.clone(), repos.clone()));
    let (state, bad_jump) = walk(&dump, &symbolizer).await?;

    let mut analysis = build(&state, stores, &repos, bad_jump);
    analysis.sys_error = sys_error_of(&dump, &state, &analysis);
    Ok(analysis)
}

/// Every thread walked, plus the recovery for a jump to an address that is not code.
async fn walk<P>(
    dump: &Minidump<'_, Vec<u8>>,
    symbols: &P,
) -> anyhow::Result<(ProcessState, bool)>
where
    P: SymbolProvider + Sync,
{
    let mut state = minidump_processor::process_minidump(dump, symbols)
        .await
        .context("processing failed")?;
    let bad_jump = match bad_jump_frames(dump, &state, symbols).await {
        Some((thread, frames)) => {
            let stack = &mut state.threads[thread];
            stack.frames.truncate(1);
            stack.frames.extend(frames);
            true
        }
        None => false,
    };
    Ok((state, bad_jump))
}

/// Largest report returned, so a dump with thousands of threads cannot fill the response.
const MAX_RAW_BYTES: usize = 8 << 20;

/// What `minidump_stackwalk` prints for the dump: the crash reason, the system, every
/// thread's stack and the modules. Frames are symbolized as for the crash page, and the
/// bad-jump recovery applies. Nothing from the process's memory (command line, environment).
pub async fn raw_text(path: &Path, stores: &SymbolStores) -> anyhow::Result<String> {
    let bytes = tokio::fs::read(path)
        .await
        .with_context(|| format!("reading {}", path.display()))?;
    let dump = Minidump::read(bytes).context("not a valid minidump")?;
    let repos = RepoMap::default();
    let symbolizer = Symbolizer::new(StoreSupplier::new(stores.clone(), repos));
    let (state, _) = walk(&dump, &symbolizer).await?;

    let mut out = Vec::new();
    state.print(&mut out).context("printing the report")?;
    let mut text = String::from_utf8_lossy(&out).into_owned();
    if text.len() > MAX_RAW_BYTES {
        let mut end = MAX_RAW_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("\n... (truncated)\n");
    }
    Ok(text)
}

/// Only when the top frame of the shown thread is the engine's `Sys_Error`.
fn sys_error_of(
    dump: &Minidump<'_, Vec<u8>>,
    state: &ProcessState,
    a: &Analysis,
) -> Option<String> {
    let top = a
        .frames
        .iter()
        .find(|f| f.thread == a.thread && f.frame == 0)?;
    if !super::sys_error::is_sys_error_frame(&top.module, &top.function) {
        return None;
    }
    super::sys_error::extract(dump, state, usize::try_from(a.thread).ok()?)
}

fn sym_path(module: &MinidumpModule) -> Option<String> {
    breakpad_sym_lookup(module).map(|l| l.cache_rel)
}

fn module_rows(state: &ProcessState, stores: &SymbolStores) -> Vec<ModuleRow> {
    let mut seen = BTreeSet::new();
    let mut rows = Vec::new();
    for m in state.modules.iter() {
        let (Some(debug_file), Some(id)) = (m.debug_file(), m.debug_identifier()) else {
            continue;
        };
        let name = render::basename(&debug_file).to_string();
        let identifier = id.breakpad().to_string();
        if name.is_empty() || !seen.insert((name.clone(), identifier.clone())) {
            continue;
        }
        let present = sym_path(m).is_some_and(|rel| stores.find(&rel).is_some());
        rows.push(ModuleRow {
            name,
            identifier,
            base: format!("0x{:x}", m.base_address()),
            present,
        });
    }
    rows
}

fn frame_row(thread: usize, index: usize, f: &StackFrame, repos: &RepoMap) -> FrameRow {
    let module = f.module.as_ref();
    let module_name = module
        .map(|m| render::basename(&m.code_file()).to_string())
        .unwrap_or_default();
    let function = f
        .function_name
        .as_deref()
        .map(|n| render::shorten(&render::strip_separators(n)))
        .unwrap_or_default();
    let file = f
        .source_file_name
        .as_deref()
        .map(render::strip_separators)
        .unwrap_or_default();
    let line = f.source_line.unwrap_or(0);

    // Same rule as Breakpad's machine-readable output. Breakpad prints the
    // return address; rust-minidump's `instruction` is the call site (return
    // address - 1, used for symbol lookup), so offsets use `resume_address`.
    let address = f.resume_address;
    let offset = match module {
        Some(_) if !function.is_empty() => {
            let base = if file.is_empty() {
                f.function_base
            } else {
                f.source_line_base
            };
            address.wrapping_sub(base.unwrap_or(0))
        }
        Some(m) => address.wrapping_sub(m.base_address()),
        None => address,
    };
    let offset = format!("0x{offset:x}");

    let rendered = render::render(&FrameParts {
        module: &module_name,
        function: &function,
        file: &file,
        line,
        offset: &offset,
    });

    let url = match module {
        Some(m) if !file.is_empty() => sym_path(m)
            .and_then(|rel| {
                let map = repos.lock().unwrap_or_else(|p| p.into_inner());
                map.get(&rel).cloned()
            })
            .and_then(|r| repo::source_url(&r, &file, line)),
        _ => None,
    };

    FrameRow {
        thread: thread as i64,
        frame: index as i64,
        module: module_name,
        function,
        file,
        line: i64::from(line),
        offset,
        rendered,
        url,
    }
}

/// A call through a bad function pointer leaves the instruction pointer at an address
/// that is neither code nor mapped memory. There is nothing to unwind from, and the walker
/// follows the frame pointer of a callee that never existed, into junk. But the `call`
/// pushed its return address: when the word at the stack pointer points into a loaded
/// module, the walk restarts from it, so the trace shows who made the call.
///
/// Returns the thread and its frames from the return address on (the broken first frame
/// is kept by the caller). `None` when this is not that situation.
async fn bad_jump_frames<P>(
    dump: &Minidump<'_, Vec<u8>>,
    state: &ProcessState,
    symbols: &P,
) -> Option<(usize, Vec<StackFrame>)>
where
    P: SymbolProvider + Sync,
{
    let thread = state
        .requesting_thread
        .filter(|&t| t < state.threads.len())
        .unwrap_or(0);
    let stack = state.threads.get(thread)?;
    let top = stack.frames.first()?;
    if top.module.is_some() {
        return None;
    }

    // Code outside any module (a JIT, say) is still in the dump's memory.
    let memory = dump.get_memory().unwrap_or_default();
    if memory
        .memory_at_address(top.context.get_instruction_pointer())
        .is_some()
    {
        return None;
    }

    let sp = top.context.get_stack_pointer();
    let threads = dump.get_stream::<MinidumpThreadList>().ok()?;
    let mut stack_memory = threads.threads.get(thread)?.stack_memory(&memory);
    if stack_memory
        .as_ref()
        .and_then(|m| m.get_memory_at_address::<u8>(sp))
        .is_none()
    {
        stack_memory = memory.memory_at_address(sp).or(stack_memory);
    }
    let stack_memory = stack_memory?;

    let (ret, popped) = match &top.context.raw {
        MinidumpRawContext::X86(_) => {
            (u64::from(stack_memory.get_memory_at_address::<u32>(sp)?), 4)
        }
        MinidumpRawContext::Amd64(_) => (stack_memory.get_memory_at_address::<u64>(sp)?, 8),
        _ => return None,
    };
    let call_site = ret.saturating_sub(1);
    state.modules.module_at_address(call_site)?;

    let mut context = top.context.clone();
    let new_sp = sp.checked_add(popped)?;
    match &mut context.raw {
        MinidumpRawContext::X86(c) => {
            c.eip = u32::try_from(ret).ok()?;
            c.esp = u32::try_from(new_sp).ok()?;
        }
        MinidumpRawContext::Amd64(c) => {
            c.rip = ret;
            c.rsp = new_sp;
        }
        _ => return None,
    }

    let mut callers = CallStack::with_context(context);
    callers.thread_id = stack.thread_id;
    callers.thread_name.clone_from(&stack.thread_name);
    let first = callers.frames.first_mut()?;
    // Not given by a context, but found on the stack. Symbols are looked up one byte
    // before a return address, as the walker does for every caller.
    first.trust = FrameTrust::Scan;
    first.instruction = call_site;

    walk_stack(
        thread,
        (),
        &mut callers,
        Some(stack_memory),
        &state.modules,
        &state.system_info,
        symbols,
    )
    .await;
    Some((thread, callers.frames))
}

pub fn build(
    state: &ProcessState,
    stores: &SymbolStores,
    repos: &RepoMap,
    bad_jump: bool,
) -> Analysis {
    let display = state
        .requesting_thread
        .filter(|&t| t < state.threads.len())
        .unwrap_or(0);

    let mut kept = vec![0, display];
    kept.dedup();

    let mut frames = Vec::new();
    for &t in &kept {
        let Some(stack) = state.threads.get(t) else {
            continue;
        };
        for (i, f) in stack.frames.iter().enumerate().take(MAX_FRAMES_PER_THREAD) {
            frames.push(frame_row(t, i, f, repos));
        }
    }

    let thread = display as i64;
    // After a bad jump the first frame is the bad address itself: the crash is
    // better known by the code that called it.
    let top_frame = i64::from(bad_jump);
    let top = frames
        .iter()
        .find(|f| f.thread == thread && f.frame == top_frame);
    let crash_module = top.map(|f| f.module.clone()).filter(|m| !m.is_empty());
    let crash_function = top.map(|f| {
        if f.function.is_empty() {
            f.offset.clone()
        } else {
            f.function.clone()
        }
    });

    let stackhash = render::stackhash(
        frames
            .iter()
            .filter(|f| f.thread == thread && f.frame < HASH_FRAMES && !f.module.is_empty())
            .map(|f| f.rendered.as_str()),
    );

    Analysis {
        thread,
        modules: module_rows(state, stores),
        frames,
        crash_module,
        crash_function,
        stackhash,
        sys_error: None,
        crash_reason: state.exception_info.as_ref().map(|e| e.reason.to_string()),
        crash_address: state
            .exception_info
            .as_ref()
            .map(|e| format!("0x{:x}", e.address.0)),
        bad_jump,
    }
}

/// `analyze` end to end on x86 dumps built with minidump-synth.
#[cfg(test)]
mod bad_jump_tests {
    use super::{Analysis, analyze};
    use crate::process::supplier::SymbolStores;
    use minidump_synth::{DumpString, Memory, Module, SynthMinidump, SystemInfo, Thread};
    use test_assembler::{Endian, Section};

    const BASE: u32 = 0x1000;
    const MODULE: u32 = 0x5000;
    const NOWHERE: u32 = 0x0280_0001;

    /// 0x1000..0x1240. The word at esp (BASE + 0x10) is `ret`; the frame pointer
    /// (BASE + 0x80) is a decoy that leads to 0x5800, inside the module too.
    fn stack(ret: u32) -> Memory {
        let section = Section::with_endian(Endian::Little)
            .append_repeated(0, 0x10)
            .D32(ret)
            .append_repeated(0, 0x80 - 0x14)
            .D32(0) // saved ebp
            .D32(0x5800) // the callee's return address, as far as the frame pointer knows
            .append_repeated(0, 0x200);
        Memory::with_section(section, u64::from(BASE))
    }

    /// CONTEXT_X86 with the given registers (all others zero).
    fn x86(eip: u32, ebp: u32, esp: u32) -> Section {
        let section = Section::with_endian(Endian::Little)
            .D32(0x1003f) // context_flags
            .append_repeated(0, 4 * 6) // dr0-3, dr6, dr7
            .append_repeated(0, 112) // float_save
            .append_repeated(0, 4 * 4) // gs, fs, es, ds
            .append_repeated(0, 4 * 6) // edi, esi, ebx, edx, ecx, eax
            .D32(ebp)
            .D32(eip)
            .D32(0) // cs
            .D32(0) // eflags
            .D32(esp)
            .D32(0) // ss
            .append_repeated(0, 512);
        assert_eq!(section.size(), 716);
        section
    }

    async fn analysis(eip: u32, ret: u32) -> Analysis {
        let stack = stack(ret);
        let context = x86(eip, BASE + 0x80, BASE + 0x10);
        let thread = Thread::new(Endian::Little, 0x1234, &stack, &context);
        let name = DumpString::new("/srv/server_srv.so", Endian::Little);
        let module = Module::new(Endian::Little, u64::from(MODULE), 0x1000, &name, 0, 0, None);
        let dump = SynthMinidump::with_endian(Endian::Little)
            .add_thread(thread)
            .add_system_info(SystemInfo::new(Endian::Little))
            .add_module(module)
            .add(name)
            .add(context)
            .add_memory(stack);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synth.dmp");
        std::fs::write(&path, dump.finish().unwrap()).unwrap();
        analyze(&path, &SymbolStores::new(Vec::new(), 1 << 20))
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_jump_to_nowhere_is_unwound_from_the_return_address_on_the_stack() {
        let a = analysis(NOWHERE, MODULE + 0x10).await;
        assert!(a.bad_jump);
        let frames: Vec<_> = a.frames.iter().filter(|f| f.thread == 0).collect();
        // The bad address itself, then the code that called it (not the decoy at 0x5800).
        assert_eq!(
            (frames[0].module.as_str(), frames[0].offset.as_str()),
            ("", "0x2800001")
        );
        assert_eq!(
            (frames[1].module.as_str(), frames[1].offset.as_str()),
            ("server_srv.so", "0x10")
        );
        assert_eq!(a.crash_module.as_deref(), Some("server_srv.so"));
        assert_eq!(a.crash_function.as_deref(), Some("0x10"));
    }

    #[tokio::test]
    async fn an_address_inside_a_module_is_left_alone() {
        let a = analysis(MODULE + 0x20, MODULE + 0x10).await;
        assert!(!a.bad_jump);
        assert_eq!(a.crash_module.as_deref(), Some("server_srv.so"));
        assert_eq!(a.crash_function.as_deref(), Some("0x20"));
    }

    #[tokio::test]
    async fn without_a_return_address_in_a_module_nothing_is_recovered() {
        let a = analysis(NOWHERE, 0x9999).await;
        assert!(!a.bad_jump);
        assert_eq!(a.crash_module, None);
    }
}
