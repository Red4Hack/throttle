//! Optional deep analysis of a dump with the external `carburetor` program
//! (github.com/asherkin/carburetor: Breakpad plus SourcePawn plugin frames,
//! registers, stack memory and disassembly). It is a C++ program parsing
//! untrusted dumps, so it is treated as hostile-input code:
//!
//! * it is only ever started from a path in the configuration, directly (no
//!   shell), with an empty environment, no stdin and its stderr discarded;
//! * the only arguments are flags we choose, the dump path we build from a
//!   validated crash ID, and the configured symbol directories;
//! * a run has a time limit, an output size limit, and at most
//!   `carburetor.max_concurrent` run at once (the rest are told to try later);
//! * on any limit the process is killed.
//!
//! Without `carburetor.path` the feature does not exist (the pages answer 404).

use std::fmt::Write as _;
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;
use serde_json::Value;
use tokio::io::AsyncReadExt;
use tokio::process::Command;

use crate::app::AppState;

#[derive(Debug, PartialEq, Eq)]
pub enum RunError {
    Disabled,
    /// All run slots are taken.
    Busy,
    TimedOut,
    TooBig,
    /// It could not be started, or it exited with an error.
    Failed,
}

/// Run the program on the dump of `id` and return what it printed (JSON).
/// `full` also asks for the stack memory and disassembly, which is big.
pub async fn run(state: &AppState, id: &str, full: bool) -> Result<Vec<u8>, RunError> {
    let cfg = &state.config;
    let bin = cfg.carburetor.path.as_ref().ok_or(RunError::Disabled)?;
    let _slot = state
        .carburetor_runs
        .try_acquire()
        .map_err(|_| RunError::Busy)?;

    let mut cmd = Command::new(bin);
    if !full {
        cmd.args(["--no-memory", "--no-instructions"]);
    }
    cmd.arg(cfg.dump_path(id))
        .args(cfg.symbol_store_dirs())
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true);

    let mut child = cmd.spawn().map_err(|e| {
        tracing::error!(error = %e, "could not start carburetor");
        RunError::Failed
    })?;
    let mut stdout = child.stdout.take().ok_or(RunError::Failed)?;
    let max = cfg.carburetor.max_output_bytes;

    let work = async {
        let mut out = Vec::new();
        (&mut stdout)
            .take(max.saturating_add(1))
            .read_to_end(&mut out)
            .await
            .map_err(|_| RunError::Failed)?;
        if out.len() as u64 > max {
            return Err(RunError::TooBig);
        }
        let status = child.wait().await.map_err(|_| RunError::Failed)?;
        if status.success() {
            Ok(out)
        } else {
            tracing::warn!(%status, %id, "carburetor failed");
            Err(RunError::Failed)
        }
    };
    // Dropping `child` on any early return or timeout kills the process.
    match tokio::time::timeout(Duration::from_secs(cfg.carburetor.timeout_secs), work).await {
        Ok(result) => result,
        Err(_) => Err(RunError::TimedOut),
    }
}

const MAX_TEXT_CHARS: usize = 500;
/// The most text one tab shows. The complete output is the JSON download.
const MAX_TAB_BYTES: usize = 8 << 20;

/// What the "View Raw" page shows, from the program's JSON: the three tabs the PHP site's
/// JavaScript viewer had. The text is plain; escaping it is the template's job.
#[derive(Debug, Default, Serialize)]
pub struct Viewer {
    /// The crash reason, then every thread: frames, registers, disassembly, stack memory.
    pub stack: String,
    /// A hex dump of every memory region of the dump.
    pub memory: String,
    /// The JSON itself, indented.
    pub raw: String,
}

/// Breakpad's `StackFrame::FrameTrust`, in the words of the old viewer.
const TRUST: [&str; 7] = [
    "unknown",
    "stack scanning",
    "call frame info with scanning",
    "previous frame's frame pointer",
    "call frame info",
    "external stack walker",
    "instruction pointer in context",
];

/// Registers come out in this order, the others after them.
const REGISTER_ORDER: &[&str] = &[
    "eip", "esp", "ebp", "ebx", "esi", "edi", "eax", "ecx", "edx", "efl", "rax", "rdx", "rcx",
    "rbx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip",
];

/// Text that stops growing at `cap` bytes.
struct Out {
    text: String,
    cap: usize,
    cut: bool,
}

impl Out {
    fn new(cap: usize) -> Self {
        Self {
            text: String::new(),
            cap,
            cut: false,
        }
    }

    fn full(&mut self) -> bool {
        if self.text.len() >= self.cap {
            self.cut = true;
        }
        self.cut
    }

    fn line(&mut self, line: impl AsRef<str>) {
        if self.full() {
            return;
        }
        self.text.push_str(line.as_ref());
        self.text.push('\n');
    }

    fn finish(mut self) -> String {
        if self.cut {
            self.text
                .push_str("... cut here; the complete output is in the full data (JSON).\n");
        }
        self.text
    }
}

/// A writer that takes at most `cap` bytes, then refuses more.
struct Capped {
    bytes: Vec<u8>,
    cap: usize,
}

impl std::io::Write for Capped {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        let room = self.cap.saturating_sub(self.bytes.len());
        let n = data.len().min(room);
        self.bytes.extend_from_slice(&data[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn clip(s: &str) -> String {
    s.chars().take(MAX_TEXT_CHARS).collect()
}

fn str_of(v: &Value, key: &str) -> String {
    v.get(key)
        .and_then(Value::as_str)
        .map(clip)
        .unwrap_or_default()
}

/// Standard or URL-safe base64, padded or not; whitespace is skipped.
fn base64(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let (mut acc, mut bits) = (0_u32, 0_u32);
    for b in s.bytes() {
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' | b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(u8::try_from(acc >> bits).ok()?);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// `address  hex bytes  text`, `row` bytes to a line, a gap every eight.
fn hex_dump(out: &mut Out, indent: &str, base: u64, data: &[u8], row: usize) {
    let width = if base > u64::from(u32::MAX) { 16 } else { 8 };
    for (n, chunk) in data.chunks(row).enumerate() {
        if out.full() {
            return;
        }
        let at = base.wrapping_add(n as u64 * row as u64);
        let mut line = format!("{indent}{at:0width$x}  ");
        let mut text = String::with_capacity(row);
        for i in 0..row {
            if let Some(&b) = chunk.get(i) {
                let _ = write!(line, "{b:02x} ");
                text.push(if (0x20..0x7f).contains(&b) {
                    char::from(b)
                } else {
                    '.'
                });
            } else {
                line.push_str("   ");
                text.push(' ');
            }
            if i + 1 < row && i % 8 == 7 {
                line.push(' ');
            }
        }
        line.push(' ');
        line.push_str(&text);
        out.line(line);
    }
}

fn print_registers(out: &mut Out, indent: &str, regs: &serde_json::Map<String, Value>) {
    let mut names: Vec<&str> = REGISTER_ORDER
        .iter()
        .copied()
        .filter(|n| regs.get(*n).is_some_and(Value::is_u64))
        .collect();
    for (name, value) in regs {
        if value.is_u64() && !names.contains(&name.as_str()) {
            names.push(name);
        }
    }
    for row in names.chunks(4) {
        let line: Vec<String> = row
            .iter()
            .map(|n| {
                let value = regs.get(*n).and_then(Value::as_u64).unwrap_or(0);
                format!("{}: 0x{value:08x}", clip(n))
            })
            .collect();
        out.line(format!("{indent}{}", line.join("  ")));
    }
}

/// Up to five instructions either side of the crashing one, which is marked with `>`.
fn print_instructions(out: &mut Out, indent: &str, ip: u64, instructions: &[Value]) {
    let rows: Vec<(u64, String, &str)> = instructions
        .iter()
        .filter_map(|i| {
            Some((
                i.get("offset")?.as_u64()?,
                i.get("hex")?.as_str()?.chars().take(64).collect(),
                i.get("mnemonic").and_then(Value::as_str).unwrap_or(""),
            ))
        })
        .collect();
    if rows.is_empty() {
        return;
    }
    let crash = (0..rows.len())
        .find(|&i| ip >= rows[i].0 && rows.get(i + 1).is_none_or(|next| ip < next.0));
    let shown = match crash {
        Some(c) => c.saturating_sub(5)..(c + 6).min(rows.len()),
        None => 0..rows.len(),
    };
    let bytes_per_line = rows[shown.clone()]
        .iter()
        .map(|r| r.1.len() / 2)
        .max()
        .unwrap_or(0);
    let pad = (bytes_per_line * 3).saturating_sub(1);
    for i in shown {
        let (offset, hex, mnemonic) = &rows[i];
        let lead = if Some(i) == crash {
            format!("  >{}", indent.get(3..).unwrap_or(""))
        } else {
            indent.to_string()
        };
        let bytes = hex
            .as_bytes()
            .chunks(2)
            .map(String::from_utf8_lossy)
            .collect::<Vec<_>>()
            .join(" ");
        out.line(format!(
            "{lead}{offset:08x}  {bytes:<pad$}  {}",
            clip(mnemonic)
        ));
    }
}

fn trust(f: &Value) -> &'static str {
    let n = f.get("trust").and_then(Value::as_u64).unwrap_or(0);
    usize::try_from(n)
        .ok()
        .and_then(|n| TRUST.get(n))
        .copied()
        .unwrap_or(TRUST[0])
}

fn rendered(f: &Value) -> String {
    let text = str_of(f, "rendered");
    if !text.is_empty() {
        return text;
    }
    f.get("instruction")
        .or_else(|| f.get("return_address"))
        .and_then(Value::as_u64)
        .map_or_else(|| "?".to_string(), |a| format!("{a:#x}"))
}

fn print_thread(out: &mut Out, index: usize, crashed: bool, frames: &Value) {
    let frames = frames.as_array().map(Vec::as_slice).unwrap_or(&[]);
    out.line(format!(
        "Thread {index}{}:",
        if crashed { " (crashed)" } else { "" }
    ));
    let width = frames.len().saturating_sub(1).to_string().len();
    for (i, f) in frames.iter().enumerate() {
        if out.full() {
            return;
        }
        let prefix = format!("{i:>width$}: ");
        let indent = " ".repeat(2 + prefix.len());
        out.line(format!("  {prefix}{}", rendered(f)));

        if let Some(url) = f.get("url").and_then(Value::as_str) {
            out.line(format!("{indent}{}", clip(url)));
        }
        if let Some(p) = f.get("plugin").filter(|p| p.is_object()) {
            let (file, function) = (str_of(p, "file"), str_of(p, "function"));
            let what = if function.is_empty() {
                file
            } else {
                format!("{file}: {function}")
            };
            out.line(format!("{indent}SourcePawn: {what}"));
        }

        let registers = f.get("registers").and_then(Value::as_object);
        if let Some(regs) = registers {
            print_registers(out, &indent, regs);
            out.line("");
        }
        if let Some(instructions) = f.get("instructions").and_then(Value::as_array) {
            let ip = f.get("instruction").and_then(Value::as_u64).unwrap_or(0);
            print_instructions(out, &indent, ip, instructions);
            out.line("");
        }
        if let Some(bytes) = f.get("stack").and_then(Value::as_str).and_then(base64) {
            // The stack memory starts where the stack pointer is.
            let base = registers
                .and_then(|r| r.get("esp").or_else(|| r.get("rsp")))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            hex_dump(out, &indent, base, &bytes, 16);
            out.line("");
        }
        out.line(format!("{indent}Found via {}", trust(f)));
        out.line("");
        out.line("");
    }
}

fn stack_tab(v: &Value, cap: usize) -> String {
    let mut out = Out::new(cap);
    if v.get("crashed").and_then(Value::as_bool) == Some(true) {
        let reason = str_of(v, "crash_reason");
        let address = v.get("crash_address").and_then(Value::as_u64).unwrap_or(0);
        out.line(format!("{reason} accessing {address:#x}"));
        out.line("");
    }
    let threads = v
        .get("threads")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[]);
    let crashing = v
        .get("requesting_thread")
        .and_then(Value::as_u64)
        .and_then(|t| usize::try_from(t).ok())
        .filter(|&t| t < threads.len());
    if let Some(t) = crashing {
        print_thread(&mut out, t, true, &threads[t]);
    }
    for (i, t) in threads.iter().enumerate() {
        if Some(i) != crashing {
            print_thread(&mut out, i, false, t);
        }
    }
    out.finish()
}

fn memory_tab(v: &Value, cap: usize) -> String {
    let mut out = Out::new(cap);
    let mut regions: Vec<(u64, u64, &str)> = v
        .get("memory")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| {
            Some((
                r.get("base")?.as_u64()?,
                r.get("size").and_then(Value::as_u64).unwrap_or(0),
                r.get("data")?.as_str()?,
            ))
        })
        .collect();
    if regions.is_empty() {
        out.line("No memory regions in input");
        return out.finish();
    }
    regions.sort_by_key(|r| r.0);

    let start = regions[0].0;
    let end = regions
        .iter()
        .map(|r| r.0.saturating_add(r.1))
        .max()
        .unwrap_or(start);
    let real = regions.iter().fold(0_u64, |a, r| a.saturating_add(r.1));
    let span = end.saturating_sub(start);
    let coverage = if span == 0 {
        0.0
    } else {
        real as f64 * 100.0 / span as f64
    };
    out.line(format!(
        "Got {real} bytes of memory covering {start:08x} to {end:08x} ({coverage:.1}% coverage)"
    ));
    out.line("");

    for (base, _, data) in regions {
        if out.full() {
            break;
        }
        match base64(data) {
            Some(bytes) => hex_dump(&mut out, "", base, &bytes, 32),
            None => out.line(format!("{base:08x}  (unreadable)")),
        }
        out.line("");
    }
    out.finish()
}

fn raw_tab(v: &Value, cap: usize) -> String {
    let mut buf = Capped {
        bytes: Vec::new(),
        cap,
    };
    let complete = serde_json::to_writer_pretty(&mut buf, v).is_ok();
    let mut text = String::from_utf8_lossy(&buf.bytes).into_owned();
    if !complete {
        text.push_str("\n... cut here; the complete output is in the full data (JSON).\n");
    }
    text
}

/// The three tabs from the program's JSON. Everything is optional: the output format is
/// the program's, and a missing field is not an error. `None` when it is not a JSON object.
pub fn viewer(json: &[u8]) -> Option<Viewer> {
    viewer_capped(json, MAX_TAB_BYTES)
}

fn viewer_capped(json: &[u8], cap: usize) -> Option<Viewer> {
    let v: Value = serde_json::from_slice(json).ok()?;
    if !v.is_object() {
        return None;
    }
    Some(Viewer {
        stack: stack_tab(&v, cap),
        memory: memory_tab(&v, cap),
        raw: raw_tab(&v, cap),
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::OnceLock;

    use tempfile::TempDir;

    use super::*;
    use crate::config::Config;
    use crate::db;
    use crate::ingest::token::Secret;

    const REAL: &str = include_str!("../tests/fixtures/carburetor/real.json");
    const PLUGIN: &str = r#"{
        "crash_reason": "<script>alert(1)</script>",
        "crash_address": 0,
        "requesting_thread": 1,
        "system_info": {"os": "Linux", "cpu": "amd64"},
        "modules_without_symbols": [{"debug_file": "libc.so.6"}, {"code_file": "x.so"}, {}],
        "threads": [
            [{"rendered": "main thread frame", "trust": 6}],
            [{"rendered": "sourcepawn.jit.x64!sp::PluginContext::Invoke", "trust": 4,
              "registers": {"rip": 4096, "rsp": 65536, "note": "not a number"}},
             {"instruction": 255, "plugin": {"file": "plugin.smx", "function": "OnPluginStart"}},
             {}]
        ]
    }"#;

    /// Stands in for the real program; the first line of the dump picks what it does.
    const SCRIPT: &str = r#"#!/bin/sh
PATH=/usr/bin:/bin
dir=$(dirname "$0")
for a in "$@"; do case "$a" in -*) ;; *) dump="$a"; break ;; esac; done
mode=$(head -n 1 "$dump")
case "$mode" in
  real|plugin) cat "$dir/$mode.json" ;;
  args) printf '{"args":"%s"}' "$*" ;;
  sleep) exec sleep 30 ;;
  big) head -c 5000 /dev/zero | tr '\0' x ;;
  fail) echo boom >&2; exit 3 ;;
  *) echo 'not json' ;;
esac
"#;

    /// Written once, before any test starts the script (writing an executable
    /// while another thread forks can make exec fail with ETXTBSY).
    pub(crate) fn fake() -> &'static Path {
        static FAKE: OnceLock<(TempDir, PathBuf)> = OnceLock::new();
        &FAKE
            .get_or_init(|| {
                let dir = tempfile::tempdir().unwrap();
                std::fs::write(dir.path().join("real.json"), REAL).unwrap();
                std::fs::write(dir.path().join("plugin.json"), PLUGIN).unwrap();
                let script = dir.path().join("carburetor");
                std::fs::write(&script, SCRIPT).unwrap();
                std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
                (dir, script)
            })
            .1
    }

    struct Env {
        state: AppState,
        _dir: TempDir,
    }

    async fn setup(tweak: impl FnOnce(&mut Config)) -> Env {
        let dir = tempfile::tempdir().unwrap();
        let mut config = Config {
            data_dir: dir.path().to_path_buf(),
            ..Config::default()
        };
        config.carburetor.path = Some(fake().to_path_buf());
        config.carburetor.timeout_secs = 10;
        tweak(&mut config);
        let state = AppState::new(
            config,
            db::open_memory().await.unwrap(),
            Secret::from_bytes(vec![1; 32]),
        );
        Env { state, _dir: dir }
    }

    impl Env {
        /// A dump whose first line is `mode`.
        fn dump(&self, id: &str, mode: &str) {
            let path = self.state.config.dump_path(id);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, format!("{mode}\n")).unwrap();
        }

        async fn run(&self, mode: &str, full: bool) -> Result<Vec<u8>, RunError> {
            self.dump("aaaaaaaaaaaa", mode);
            run(&self.state, "aaaaaaaaaaaa", full).await
        }
    }

    #[tokio::test]
    async fn output_is_returned_and_viewed() {
        let env = setup(|_| {}).await;
        let out = env.run("real", false).await.unwrap();
        let v = viewer(&out).unwrap();
        assert!(v.stack.starts_with("EXCEPTION_ACCESS_VIOLATION_WRITE accessing 0x45\n"), "{}", v.stack);
        assert!(v.stack.contains("Thread 0 (crashed):"), "{}", v.stack);
        assert!(v.stack.contains("CrashFunction"), "{}", v.stack);
        assert!(v.stack.contains("eip: 0x"), "{}", v.stack);
        assert!(v.stack.contains("Found via instruction pointer in context"));
        assert!(v.raw.contains("kernel32.pdb"), "modules without symbols are in the JSON");
        assert!(v.memory.contains("No memory regions"));
    }

    #[tokio::test]
    async fn only_our_own_arguments_are_passed() {
        let env =
            setup(|c| c.processing.symbol_stores = vec!["trusted".into(), "public".into()]).await;
        let args = |out: Vec<u8>| -> String {
            let v: Value = serde_json::from_slice(&out).unwrap();
            v["args"].as_str().unwrap().to_string()
        };
        let dump = env.state.config.dump_path("aaaaaaaaaaaa");

        let short = args(env.run("args", false).await.unwrap());
        let expected = format!(
            "--no-memory --no-instructions {} {} {}",
            dump.display(),
            env.state.config.symbols_dir().join("trusted").display(),
            env.state.config.symbols_dir().join("public").display(),
        );
        assert_eq!(short, expected);

        let full = args(env.run("args", true).await.unwrap());
        assert!(!full.contains("--no-"), "{full}");
        assert!(full.starts_with(&dump.display().to_string()));
    }

    #[tokio::test]
    async fn failures_are_reported_not_hidden() {
        let env = setup(|_| {}).await;
        assert_eq!(env.run("fail", false).await, Err(RunError::Failed));
        // Output we cannot read is the page's problem, not the runner's.
        let out = env.run("garbage", false).await.unwrap();
        assert!(viewer(&out).is_none());

        let missing = setup(|c| c.carburetor.path = Some("/nonexistent/carburetor".into())).await;
        assert_eq!(missing.run("real", false).await, Err(RunError::Failed));
    }

    #[tokio::test]
    async fn the_feature_is_off_without_a_path() {
        let env = setup(|c| c.carburetor.path = None).await;
        assert_eq!(env.run("real", false).await, Err(RunError::Disabled));
    }

    #[tokio::test]
    async fn slow_runs_are_killed() {
        let env = setup(|c| c.carburetor.timeout_secs = 1).await;
        let started = std::time::Instant::now();
        assert_eq!(env.run("sleep", false).await, Err(RunError::TimedOut));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn huge_output_is_refused() {
        let env = setup(|c| c.carburetor.max_output_bytes = 1000).await;
        assert_eq!(env.run("big", false).await, Err(RunError::TooBig));
        // The limit is on the size: exactly at it is fine.
        let env = setup(|c| c.carburetor.max_output_bytes = 5000).await;
        assert_eq!(env.run("big", false).await.map(|o| o.len()), Ok(5000));
    }

    #[tokio::test]
    async fn only_so_many_runs_at_once() {
        let env = setup(|c| c.carburetor.max_concurrent = 1).await;
        let held = env.state.carburetor_runs.try_acquire().unwrap();
        assert_eq!(env.run("real", false).await, Err(RunError::Busy));
        drop(held);
        assert!(env.run("real", false).await.is_ok());
    }

    #[test]
    fn plugin_frames_and_odd_values_are_shown_safely() {
        let v = viewer(PLUGIN.as_bytes()).unwrap();
        // The requesting thread comes first, and what the program printed is not escaped here.
        assert!(v.stack.find("Thread 1 (crashed):") < v.stack.find("Thread 0:"));
        assert!(v.stack.contains("sourcepawn.jit.x64!sp::PluginContext::Invoke"));
        assert!(v.stack.contains("SourcePawn: plugin.smx: OnPluginStart"));
        assert!(v.stack.contains("1: 0xff"), "no rendered text: the address");
        assert!(v.stack.contains("2: ?"));
        assert!(v.stack.contains("Found via call frame info\n"));
        // Registers: the known ones in order, numbers only.
        assert!(v.stack.contains("rsp: 0x00010000  rip: 0x00001000"), "{}", v.stack);
        assert!(!v.stack.contains("not a number"));
        assert!(v.raw.contains("<script>alert(1)</script>"));
        assert!(v.memory.contains("No memory regions"));
    }

    #[test]
    fn memory_and_stack_bytes_are_dumped_in_hex() {
        let json = r#"{"memory": [
            {"base": 8192, "size": 3, "data": "QUJD"},
            {"base": 4096, "size": 32, "data": "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU="}],
          "threads": [[{"rendered": "f", "trust": 4, "registers": {"esp": 4096}, "stack": "QUJDRA=="}]],
          "requesting_thread": 0}"#;
        let v = viewer(json.as_bytes()).unwrap();
        // Regions come out in address order, 32 bytes to a line, a gap every 8.
        let first = v
            .memory
            .find("00001000  41 42 43 44 45 46 47 48  49 4a")
            .expect(&v.memory);
        let second = v.memory.find("00002000  41 42 43").expect(&v.memory);
        assert!(first < second);
        assert!(v.memory.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"));
        assert!(
            v.memory
                .starts_with("Got 35 bytes of memory covering 00001000 to 00002003"),
            "{}",
            v.memory
        );
        // The stack of a frame is dumped from where its stack pointer is.
        assert!(v.stack.contains("00001000  41 42 43 44 "), "{}", v.stack);
        assert!(v.stack.contains("Found via call frame info"), "{}", v.stack);
    }

    #[test]
    fn disassembly_marks_the_crashing_instruction() {
        let json = r#"{"requesting_thread": 0, "threads": [[{"rendered": "f", "instruction": 4100,
          "instructions": [
            {"offset": 4096, "hex": "90", "mnemonic": "nop"},
            {"offset": 4097, "hex": "4889e5", "mnemonic": "mov rbp, rsp"},
            {"offset": 4100, "hex": "c3", "mnemonic": "ret"}]}]]}"#;
        let stack = viewer(json.as_bytes()).unwrap().stack;
        let marked: Vec<_> = stack
            .lines()
            .filter(|l| l.trim_start().starts_with('>'))
            .collect();
        assert_eq!(marked.len(), 1, "{stack}");
        assert!(marked[0].contains("00001004") && marked[0].contains("ret"));
        assert!(stack.contains("00001001  48 89 e5  mov rbp, rsp"), "{stack}");
        assert!(
            stack.contains(&format!("00001000  90{}nop", " ".repeat(8))),
            "{stack}"
        );
    }

    #[test]
    fn the_crash_reason_heads_the_stack_tab() {
        let v = viewer(br#"{"crashed": true, "crash_reason": "SIGSEGV", "crash_address": 69, "threads": []}"#)
            .unwrap();
        assert!(v.stack.starts_with("SIGSEGV accessing 0x45\n"), "{}", v.stack);
        let long = "x".repeat(MAX_TEXT_CHARS * 3);
        let v = viewer(format!(r#"{{"crashed": true, "crash_reason": "{long}"}}"#).as_bytes())
            .unwrap();
        assert!(v.stack.lines().next().unwrap().len() < MAX_TEXT_CHARS + 30);
    }

    #[test]
    fn each_tab_is_cut_at_the_cap() {
        let frames = vec![r#"{"rendered": "some function"}"#; 500].join(",");
        let json = format!(r#"{{"threads": [[{frames}]]}}"#);
        let v = viewer_capped(json.as_bytes(), 1000).unwrap();
        assert!(v.stack.len() < 1200 && v.stack.contains("cut here"), "{}", v.stack);
        assert!(v.raw.len() < 1200 && v.raw.contains("cut here"));
        let v = viewer(json.as_bytes()).unwrap();
        assert!(!v.stack.contains("cut here") && !v.raw.contains("cut here"));
    }

    #[test]
    fn unexpected_shapes_do_not_panic() {
        for bad in ["", "null", "[]", "3", "\"x\"", "{"] {
            assert!(viewer(bad.as_bytes()).is_none(), "{bad:?}");
        }
        let v = viewer(
            br#"{"threads": "no", "requesting_thread": -1, "system_info": 5, "memory": 7}"#,
        )
        .unwrap();
        assert!(v.stack.is_empty() && v.memory.contains("No memory regions"));

        let v = viewer(
            br#"{"threads": [5, null, [1, "x"]], "requesting_thread": 9,
                 "memory": [{"base": 1}, {"base": 1, "size": 1, "data": "!!"}]}"#,
        )
        .unwrap();
        assert!(v.stack.contains("Thread 2:") && v.stack.contains("  0: ?"), "{}", v.stack);
        assert!(v.memory.contains("(unreadable)"), "{}", v.memory);
    }

    #[test]
    fn base64_is_decoded_leniently() {
        assert_eq!(base64("QUJD").unwrap(), b"ABC");
        assert_eq!(base64("QUI=").unwrap(), b"AB");
        assert_eq!(base64("QQ==").unwrap(), b"A");
        assert_eq!(base64("Q U\nJD").unwrap(), b"ABC");
        assert_eq!(base64("").unwrap(), b"");
        assert!(base64("QU*D").is_none());
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    /// Runs the real program on our own symbol store (`.sym.gz`, as `store_file`
    /// writes it) when `THROTTLE_TEST_CARBURETOR` points at a build of it.
    /// Without that variable the test is skipped.
    #[tokio::test]
    async fn the_real_program_reads_our_symbol_store() {
        let Some(bin) = std::env::var_os("THROTTLE_TEST_CARBURETOR") else {
            eprintln!("skipped: set THROTTLE_TEST_CARBURETOR to a carburetor binary to run this");
            return;
        };
        let env = setup(|c| c.carburetor.path = Some(PathBuf::from(&bin))).await;
        let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");

        let dump = env.state.config.dump_path("aaaaaaaaaaaa");
        std::fs::create_dir_all(dump.parent().unwrap()).unwrap();
        std::fs::copy(fixtures.join("dumps/test.dmp"), &dump).unwrap();

        let id = "5A9832E5287241C1838ED98914E9B7FF1";
        let sym = std::fs::read(
            fixtures
                .join("symbols/test_app.pdb")
                .join(id)
                .join("test_app.sym"),
        )
        .unwrap();
        let dir = env
            .state
            .config
            .symbols_dir()
            .join("public/test_app.pdb")
            .join(id);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("test_app.sym.gz"), gzip(&sym)).unwrap();

        let out = run(&env.state, "aaaaaaaaaaaa", false).await.unwrap();
        let stack = viewer(&out).unwrap().stack;
        assert!(
            stack.contains("CrashFunction") && stack.contains("test_app.cc:58"),
            "{stack}"
        );
        assert!(stack.contains("eip: 0x"), "{stack}");

        let full = run(&env.state, "aaaaaaaaaaaa", true).await.unwrap();
        assert!(serde_json::from_slice::<Value>(&full).is_ok());
        let view = viewer(&full).unwrap();
        assert!(view.stack.contains("Found via"), "{}", view.stack);
        assert!(
            full.len() > out.len(),
            "the full output carries the memory and disassembly too"
        );
    }
}
