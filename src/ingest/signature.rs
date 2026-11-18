//! Parser for the presubmit `CrashSignature` (format in docs/protocol.md).

use sha2::{Digest, Sha256};

pub const MAX_MODULES: usize = 4096;
pub const MAX_FRAMES: usize = 4096;
/// Frames that feed [`Signature::hash`].
const HASH_FRAMES: usize = 8;

#[derive(Debug, PartialEq, Eq)]
pub struct Module {
    pub file: String,
    pub identifier: String,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Frame {
    /// Index into `modules`, or -1 when the address is in no known module.
    pub module: i64,
    pub offset: u64,
}

#[derive(Debug)]
#[allow(dead_code)] // some fields are only read by later phases
pub struct Signature {
    pub version: u8,
    pub timestamp: i64,
    pub platform: String,
    pub architecture: String,
    pub crashed: bool,
    pub crash_reason: String,
    pub crash_address: u64,
    pub requesting_thread: i64,
    pub modules: Vec<Module>,
    pub frames: Vec<Frame>,
}

struct Fields<'a>(std::str::Split<'a, char>);

impl<'a> Fields<'a> {
    fn take(&mut self, what: &'static str) -> Result<&'a str, &'static str> {
        self.0.next().ok_or(what)
    }
}

fn int(s: &str, what: &'static str) -> Result<i64, &'static str> {
    s.parse().map_err(|_| what)
}

fn hex(s: &str, what: &'static str) -> Result<u64, &'static str> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Ok(0);
    }
    u64::from_str_radix(s, 16).map_err(|_| what)
}

/// Errors are short static strings: they go back to the client as `E|<msg>`.
pub fn parse(input: &str) -> Result<Signature, &'static str> {
    let mut f = Fields(input.trim().split('|'));

    let version = int(f.take("missing version")?, "bad version")?;
    if !(0..=2).contains(&version) {
        return Err("bad version");
    }

    let mut timestamp = 0;
    let mut platform = String::new();
    let mut architecture = String::from("x86");
    if version > 1 {
        timestamp = int(f.take("missing timestamp")?, "bad timestamp")?;
        platform = f.take("missing platform")?.to_string();
        architecture = f.take("missing architecture")?.to_string();
    }

    let crashed = int(f.take("missing crashed flag")?, "bad crashed flag")? != 0;
    let crash_reason = f.take("missing crash reason")?.to_string();
    let crash_address = hex(f.take("missing crash address")?, "bad crash address")?;
    let requesting_thread = int(f.take("missing thread")?, "bad thread")?;

    let mut modules = Vec::new();
    let mut frames = Vec::new();

    while let Some(tag) = f.0.next() {
        match tag {
            "M" => {
                if modules.len() >= MAX_MODULES {
                    return Err("too many modules");
                }
                let file = f.take("truncated module")?.to_string();
                let identifier = f.take("truncated module")?.to_string();
                if platform.is_empty() {
                    platform = match file.rsplit('.').next().unwrap_or("") {
                        "pdb" => "windows",
                        "dylib" => "mac",
                        "so" => "linux",
                        _ => "",
                    }
                    .to_string();
                }
                modules.push(Module { file, identifier });
            }
            "F" => {
                if frames.len() >= MAX_FRAMES {
                    return Err("too many frames");
                }
                let module = int(f.take("truncated frame")?, "bad frame module")?;
                let offset = hex(f.take("truncated frame")?, "bad frame offset")?;
                frames.push(Frame { module, offset });
            }
            _ => return Err("unknown field"),
        }
    }

    Ok(Signature {
        version: version as u8,
        timestamp,
        platform,
        architecture,
        crashed,
        crash_reason,
        crash_address,
        requesting_thread,
        modules,
        frames,
    })
}

impl Signature {
    /// A cheap fingerprint of the crash, available before the dump is
    /// symbolicated: the reason plus (module, build id, offset) of the top
    /// frames. Used only for dedupe decisions, never shown to users.
    ///
    /// An address in no module moves from run to run (ASLR), so it is left out when at
    /// least two of the frames are in modules. With fewer, it is all there is to tell
    /// crashes apart (a jump to a bad address leaves one frame in code at most), so it stays.
    pub fn hash(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.crash_reason.as_bytes());
        h.update([0]);
        let anchored = self
            .frames
            .iter()
            .take(HASH_FRAMES)
            .filter(|f| {
                usize::try_from(f.module)
                    .ok()
                    .and_then(|i| self.modules.get(i))
                    .is_some()
            })
            .count()
            >= 2;
        for frame in self.frames.iter().take(HASH_FRAMES) {
            let module = usize::try_from(frame.module)
                .ok()
                .and_then(|i| self.modules.get(i));
            match module {
                Some(m) => {
                    h.update(m.file.as_bytes());
                    h.update([0]);
                    h.update(m.identifier.as_bytes());
                    h.update(frame.offset.to_le_bytes());
                }
                None => {
                    h.update(b"?");
                    if !anchored {
                        h.update(frame.offset.to_le_bytes());
                    }
                }
            }
        }
        hex::encode(&h.finalize()[..8])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V2: &str = "2|1700000000|linux|amd64|1|SIGSEGV /0x00000000|7f00|3\
        |M|server_srv.so|AAAABBBBCCCCDDDDEEEEFFFF000011112\
        |M|libc.so.6|0123456789ABCDEF0123456789ABCDEF0\
        |F|0|1d72|F|1|f302e|F|-1|400000";

    #[test]
    fn parses_v2() {
        let s = parse(V2).unwrap();
        assert_eq!(s.version, 2);
        assert_eq!(s.timestamp, 1_700_000_000);
        assert_eq!(s.platform, "linux");
        assert_eq!(s.architecture, "amd64");
        assert!(s.crashed);
        assert_eq!(s.crash_reason, "SIGSEGV /0x00000000");
        assert_eq!(s.crash_address, 0x7f00);
        assert_eq!(s.requesting_thread, 3);
        assert_eq!(s.modules.len(), 2);
        assert_eq!(s.modules[0].file, "server_srv.so");
        assert_eq!(
            s.frames[2],
            Frame {
                module: -1,
                offset: 0x400000
            }
        );
    }

    #[test]
    fn parses_v0_and_infers_platform() {
        let s = parse("0|0|SIGSEGV|0|0|M|engine.so|ABC|F|0|10").unwrap();
        assert_eq!(s.platform, "linux");
        assert_eq!(s.architecture, "x86");
        assert_eq!(s.frames.len(), 1);
    }

    #[test]
    fn rejects_malformed() {
        assert_eq!(parse("").unwrap_err(), "bad version");
        assert_eq!(parse("3|x").unwrap_err(), "bad version");
        assert_eq!(parse("2|1|linux").unwrap_err(), "missing architecture");
        assert_eq!(
            parse("2|1|linux|amd64|1|r|0|0|X").unwrap_err(),
            "unknown field"
        );
        assert_eq!(
            parse("2|1|linux|amd64|1|r|0|0|M|only").unwrap_err(),
            "truncated module"
        );
        assert_eq!(
            parse("2|1|linux|amd64|1|r|zz|0").unwrap_err(),
            "bad crash address"
        );
    }

    #[test]
    fn caps_module_count() {
        let mut s = String::from("2|1|linux|amd64|1|r|0|0");
        for _ in 0..=MAX_MODULES {
            s.push_str("|M|a.so|AB");
        }
        assert_eq!(parse(&s).unwrap_err(), "too many modules");
    }

    #[test]
    fn hash_is_stable_and_sensitive() {
        let a = parse(V2).unwrap();
        let b = parse(V2).unwrap();
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.hash().len(), 16);

        let c = parse(&V2.replace("|F|0|1d72", "|F|0|1d73")).unwrap();
        assert_ne!(a.hash(), c.hash());
    }

    #[test]
    fn addresses_in_no_module_do_not_matter_when_the_stack_is_anchored() {
        let a = parse(V2).unwrap();
        let b = parse(&V2.replace("|F|-1|400000", "|F|-1|500000")).unwrap();
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn addresses_in_no_module_tell_crashes_apart_when_little_is_in_code() {
        const JUMP: &str = "2|1700000000|linux|x86|1|SIGSEGV /SEGV_MAPERR|2800001|0\
            |M|server_srv.so|AAAABBBBCCCCDDDDEEEEFFFF000011112\
            |F|-1|2800001|F|-1|f7efe5bc|F|0|10";
        let a = parse(JUMP).unwrap();
        assert_eq!(a.hash(), parse(JUMP).unwrap().hash());
        let b = parse(&JUMP.replace("|F|-1|2800001", "|F|-1|2800002")).unwrap();
        assert_ne!(a.hash(), b.hash());
    }
}
