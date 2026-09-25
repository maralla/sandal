//! Optional hypervisor debug tracing (stderr or `SANDAL_TRACE_FILE`).
//!
//! Enable with **`SANDAL_TRACE_CONSOLE_IO=1`**. Optional append path: **`SANDAL_TRACE_FILE=/path/to/log`**.

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

static ENABLED: OnceLock<bool> = OnceLock::new();
static SINK: OnceLock<Mutex<TraceSink>> = OnceLock::new();

struct TraceSink {
    file: Option<std::fs::File>,
}

impl TraceSink {
    fn new() -> Self {
        let file = env::var_os("SANDAL_TRACE_FILE")
            .and_then(|p| OpenOptions::new().create(true).append(true).open(p).ok());
        TraceSink { file }
    }

    fn write_line(&mut self, line: &str) {
        if let Some(f) = self.file.as_mut() {
            let _ = writeln!(f, "{line}");
        } else {
            eprintln!("{line}");
        }
    }
}

fn sink() -> &'static Mutex<TraceSink> {
    SINK.get_or_init(|| Mutex::new(TraceSink::new()))
}

/// True when `SANDAL_TRACE_CONSOLE_IO=1`.
pub fn console_io_enabled() -> bool {
    *ENABLED.get_or_init(|| {
        env::var("SANDAL_TRACE_CONSOLE_IO")
            .map(|v| v == "1")
            .unwrap_or(false)
    })
}

/// Scan guest RAM for occurrences of a kernel-log needle and dump the
/// matching lines to the trace sink, keeping `context` bytes of pre-needle
/// prefix (trimmed to the enclosing log line) so printk timestamps and the
/// device/queue name preceding the needle survive in the dump. The guest
/// kernel log ring (`__log_buf`) holds printk output even when the guest
/// vCPU is wedged in a busy-wait, so this is the only way to observe
/// guest-side state during a console wedge.
#[cfg(target_os = "linux")]
pub fn dump_guest_ram_lines(memory: &[u8], needle: &str, label: &str, max: usize, context: usize) {
    // Only when tracing to a FILE: without one the sink would eprintln! to
    // the console, and the host tty has OPOST disabled — a bare-\n line
    // there indents the guest's next output by this line's width, corrupting
    // the guest's own rendering (the artifact this diagnostic exists to
    // investigate).
    if sink().lock().map(|s| s.file.is_none()).unwrap_or(true) {
        return;
    }
    let needle = needle.as_bytes();
    let mut found: Vec<&[u8]> = Vec::new();
    let mut i = 0;
    // The guest kernel log ring lives in the kernel image, loaded at the
    // bottom of RAM; capping the scan keeps this diagnostic (which runs on
    // the net-kick thread — the console TX drainer!) bounded to a few
    // milliseconds instead of a full-RAM sweep.
    let scan_end = memory.len().min(64 << 20);
    while i < scan_end {
        let Some(o) = memory[i..scan_end]
            .windows(needle.len())
            .position(|w| w == needle)
        else {
            break;
        };
        let p = o + i;
        // Include a bounded prefix (still cut at the previous newline so we
        // never bleed into the prior log record) and up to the next newline
        // after the match.
        let line_start = memory[..p]
            .iter()
            .rposition(|&b| b == b'\n')
            .map(|s| s + 1)
            .unwrap_or(0);
        let start = line_start.max(p.saturating_sub(context));
        let end = memory[p..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|e| (p + e).min(p + 200))
            .unwrap_or(p + 200)
            .min(memory.len());
        // Skip printk FORMAT strings living in .rodata (e.g. `%s:id %u is
        // not a head!`): they match needles baked into them but are not
        // runtime log records. Real records carry rendered values.
        let candidate = &memory[start..end];
        if candidate.windows(2).any(|w| w == b"%s") || candidate.windows(2).any(|w| w == b"%u") {
            i = p + needle.len();
            continue;
        }
        found.push(candidate);
        i = p + needle.len();
        // No early break: the printk ring is circular, so "last by address"
        // is not "last by time" — collect everything and let the caller
        // keep the tail.
    }
    let skip = found.len().saturating_sub(max);
    for line in found.iter().skip(skip) {
        let s = String::from_utf8_lossy(line);
        let line = format!("RAMLOG {label}: {s}");
        if let Ok(mut g) = sink().lock() {
            g.write_line(&line);
        }
    }
}

/// Escape a byte slice for one log field (length capped).
pub fn bytes_preview(data: &[u8], max: usize) -> String {
    let mut s = String::new();
    for &b in data.iter().take(max) {
        match b {
            b'\n' => s.push_str("\\n"),
            b'\r' => s.push_str("\\r"),
            b'\t' => s.push_str("\\t"),
            0x20..=0x7e => s.push(b as char),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    if data.len() > max {
        s.push_str("...");
    }
    s
}

pub fn write_console_io(args: std::fmt::Arguments<'_>) {
    if !console_io_enabled() {
        return;
    }
    let line = format!("CONSOLE_IO: {}", args);
    if let Ok(mut g) = sink().lock() {
        g.write_line(&line);
    }
}
