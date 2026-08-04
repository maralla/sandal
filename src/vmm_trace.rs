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

/// Truncate UTF-8 text for logging (avoids huge REPL dumps in one line).
pub fn text_preview(s: &str, max_chars: usize) -> String {
    let t: String = s.chars().take(max_chars).collect();
    if s.chars().count() > max_chars {
        format!("{t}...")
    } else {
        t
    }
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
