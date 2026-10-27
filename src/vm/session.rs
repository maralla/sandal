//! The command execution line's front end 1: the session handler.
//!
//! `sandal -- <command>`'s own host side — the host stdio as a stream,
//! registered with the bridge core (the device + the exchange loop) the
//! same way the TCP proxy's accepted sockets are. The exchange loop is
//! stream-agnostic: it polls every registered stream, pumps both ways,
//! and reports the delivery — so the session handler is just a stream
//! whose read side is the host stdin and whose write side is the host
//! stdout.
//!
//! The stream's own protocol — exactly what the guest's vsockd expects:
//!
//!   - the FIRST read: the connection header ({mode, rows, cols,
//!     cmd_len}) + the command line — the mirror rule (the guest
//!     session's tty-ness mirrors this session's: `isatty(stdin)`
//!     decides the mode, a real terminal additionally carries its own
//!     geometry) — delivered WHOLE (the protocol, not the payload: the
//!     command is 2 bytes for the interactive session, and its echo is
//!     the guest's own);
//!   - every LATER read: the WHOLE available host stdin — the batch.
//!     The byte-at-a-time pace this once was kept the guest pty's echo
//!     queue from tripping the kernel's flow control, but it froze the
//!     terminal outright at the round rates (MEASURED: a tmux pane
//!     stopped reacting to ANY input). The batch needs no pacing
//!     anymore: the transport is event-driven end to end and its
//!     backpressure is the protocol's own credit window — a burst
//!     backs up against the guest pty's echo gate instead of wedging
//!     one — with the RSZ1 resize record injected ahead of it on a
//!     host resize (SIGWINCH → a flag → this read);
//!   - every write: the stream's output → the host stdout, verbatim
//!     (OPOST disabled at construction: the guest pty already formed
//!     the bytes, and the host tty re-applying ONLCR would double
//!     every newline), with the 17-byte status trailer scanned off the
//!     stream's end — the trailer's status is the process's own exit
//!     code, and nothing outlives the exit (the OS reclaims the guest
//!     RAM and the KVM fd). The scan is a WITHHOLDING scan: the guest
//!     sends the magic and the status byte as two separate packets and
//!     the bridge's rounds split at the guest's own packet boundaries,
//!     so every round withholds the longest suffix that could be the
//!     trailer's start and a real trailer never leaks a byte (a
//!     per-round "deliver what does not match" scan printed the whole
//!     magic to the terminal; see [`SessionStream::write`]).

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Result};

use crate::virtio::vsock::HostStream;

/// The 17-byte status trailer: 16 magic bytes + the status byte.
const TRAILER_MAGIC: &[u8; 16] = b"VSOCKD:EXIT:01\n\0";

/// The SIGWINCH flag: the handler only sets it (async-signal-safe); the
/// read side reads the geometry and injects the record.
static RESIZED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigwinch(_sig: i32) {
    RESIZED.store(true, Ordering::SeqCst);
}

/// The resize record: "RSZ1" + {cols: u16, rows: u16} (the guest's
/// vsockd strips and applies it via TIOCSWINSZ — the kernel SIGWINCHs
/// the session, so the session re-sizes itself exactly like a real
/// terminal).
fn rsz1_record() -> [u8; 8] {
    let mut record = [0u8; 8];
    record[..4].copy_from_slice(b"RSZ1");
    #[cfg(unix)]
    {
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) };
        record[4..6].copy_from_slice(&ws.ws_col.to_le_bytes());
        record[6..8].copy_from_slice(&ws.ws_row.to_le_bytes());
    }
    #[cfg(windows)]
    {
        // The Windows console has no TIOCGWINSZ: the default geometry —
        // the guest's vsockd applies what the record says, and 80x24 is
        // the honest default.
        record[4..6].copy_from_slice(&80u16.to_le_bytes());
        record[6..8].copy_from_slice(&24u16.to_le_bytes());
    }
    record
}

/// The session handler: the host stdio as a stream. Constructed with the
/// command (the whole command line — the mirror rule and the geometry
/// are read at construction, once).
pub(super) struct SessionStream {
    /// The pending header + command (the first read, delivered whole).
    pending: Vec<u8>,
    /// The command line, kept for the failure diagnostic (see
    /// [`SessionStream::write`] — the non-interactive path's failure
    /// must be NAMED, never silent).
    command: Vec<u8>,
    /// The mirror rule's own verdict: true when the host stdin was a
    /// real terminal (mode 0x02, the interactive pty session). The
    /// exit diagnostic is the NON-INTERACTIVE path's: there the
    /// failing command produces no visible output at all (the guest
    /// drops most of it before it ever posts), and the silence was the
    /// measured bug — the VMM names the failure itself. An interactive
    /// session names its own failures at the source (the shell's own
    /// `not found` line, visible in the terminal), and a diagnostic
    /// there would MISATTRIBUTE the status: `sandal -- sh` + a typo'd
    /// command inside produced "the workload command `sh` was not
    /// found" — a lie (`sh` ran; the typo'd command failed, visibly).
    interactive: bool,
    /// The withheld suffix: the bytes at the stream's end that could
    /// be the trailer's start (a prefix of the magic) — never more
    /// than 17 bytes, never delivered until the next round proves
    /// them one way or the other (see [`SessionStream::write`]). The
    /// bridge's outbox holds everything else undelivered.
    tail: Vec<u8>,
}

impl SessionStream {
    /// Construct the session handler for one command line: the mirror
    /// rule (the mode), the geometry (a real terminal's own), and the
    /// host tty's OPOST disabled (the output is already formed by the
    /// guest pty; the host tty re-applying ONLCR would double every
    /// newline).
    pub(super) fn new(command: &[String]) -> Result<Self> {
        let command_line = command.join(" ");
        if command_line.is_empty() {
            bail!("no command");
        }
        // The mirror rule: the guest session's tty-ness mirrors this
        // session's. A real terminal additionally carries its own
        // geometry; the header carries it to the guest pty pair.
        let interactive = unsafe { libc::isatty(0) == 1 };
        // Mode 0x03, not 0x02: the session line's pty session OWNS the
        // VM's lifetime — the command's exit ends the VM (the guest's
        // reaper ends in the exit hypercall). 0x02 is --port's pty
        // session: that VM lives (concurrent connections are the
        // point), and its reaper exits without the hypercall — the
        // guest cannot tell the front ends apart, so the mode byte is
        // the only thing that carries the ownership.
        // The geometry: TIOCGWINSZ is unix-only — Windows ships the
        // honest 80x24 default (the guest pty takes what the header
        // carries).
        #[cfg(unix)]
        let (mode, rows, cols) = if interactive {
            let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
            unsafe { libc::ioctl(0, libc::TIOCGWINSZ, &mut ws) };
            (3u8, ws.ws_row, ws.ws_col)
        } else {
            (1u8, 0, 0)
        };
        #[cfg(windows)]
        let (mode, rows, cols) = if interactive {
            (3u8, 24u16, 80u16)
        } else {
            (1u8, 0, 0)
        };
        let mut pending = Vec::with_capacity(9 + command_line.len());
        pending.push(mode);
        pending.extend_from_slice(&rows.to_le_bytes());
        pending.extend_from_slice(&cols.to_le_bytes());
        pending.extend_from_slice(&(command_line.len() as u32).to_le_bytes());
        pending.extend_from_slice(command_line.as_bytes());
        // The host tty's OPOST is the VMM's own doing (see Vmm::new:
        // the output is pre-formed by the guest pty), and its restore is
        // the VMM's own exit-path handler — this stream never touches
        // termios. What is left here is the stream's own: BOTH sides
        // NONBLOCKING (the exchange loop's round would otherwise BLOCK
        // on an empty host stdin — the whole bridge thread, hung on one
        // stream: MEASURED, the device's process pass never ran; and
        // the output side must report a full pane pty as EAGAIN so the
        // bridge parks on stdout's own POLLOUT — a blocking write would
        // hang the round, and a nonblocking write_all would lose the
        // partial count and duplicate the output: MEASURED, the
        // flashing pane), and the resize signal armed (the handler only
        // sets the flag).
        #[cfg(unix)]
        unsafe {
            for fd in [0, 1] {
                let fl = libc::fcntl(fd, libc::F_GETFL);
                let _ = libc::fcntl(fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
            }
            libc::signal(
                libc::SIGWINCH,
                on_sigwinch as extern "C" fn(i32) as libc::sighandler_t,
            );
        }
        Ok(Self {
            pending,
            command: command_line.into_bytes(),
            interactive,
            tail: Vec::new(),
        })
    }
}

impl Read for SessionStream {
    /// The read side: the host stdin, BATCHED. The FIRST read delivers
    /// the header + command WHOLE (the protocol); every later read
    /// delivers the WHOLE available stdin — the batch. The
    /// byte-at-a-time pace this once was kept the guest pty's echo
    /// queue from tripping the kernel's flow control, but it made the
    /// input one byte per round and the terminal froze outright at the
    /// round rates (MEASURED: a tmux pane stopped reacting to ANY
    /// input); the vsockd bridge now drives both transport gates per
    /// round, so the batch is safe.
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // The pending header + command: delivered whole.
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.len());
            buf[..n].copy_from_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Ok(n);
        }
        // A resize: the record ahead of the input (the guest's vsockd
        // strips and applies it).
        if RESIZED.swap(false, Ordering::SeqCst) {
            let record = rsz1_record();
            let n = record.len().min(buf.len());
            buf[..n].copy_from_slice(&record[..n]);
            return Ok(n);
        }
        // The WHOLE available host stdin — the batch. EAGAIN (the
        // empty host stdin) is EOF to the exchange loop's round: the
        // round proceeds to the device's process pass (the input's own
        // delivery chain), never a block.
        //
        // A CLOSED stdin (read() = 0, or any other refusal) is the
        // same verdict — NO INPUT THIS ROUND, never a session end: the
        // command was already delivered whole in the first read, its
        // output must keep flowing, and the trailer is the only end
        // there is. Mapping EOF to a fatal error let the bridge mark
        // the host side closed and RST the guest's socket — the
        // command's stdio died with it and the VMM hung forever
        // (MEASURED: `sandal -- cmd </dev/null` produced no output and
        // never exited).
        //
        // The batch (not the byte-at-a-time pace this once was): the
        // pace was a flow-control workaround for a transport whose
        // output gate stalled — one byte per round so the echo queue
        // never filled — and at the round rates it produced
        // (100 ms/pole) a terminal froze outright (MEASURED: a tmux
        // pane stopped reacting to ANY input). The transport is now
        // event-driven end to end, and its backpressure is the
        // protocol's own credit window, so the burst is safe.
        let n = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len() as _) };
        if n < 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
        }
        // EOF (n == 0) is a REAL signal: the bridge distinguishes it
        // from EAGAIN via eof_is_hangup (false here) — the session's
        // stdin ending never closes the session (the command's output
        // must keep flowing), and the bridge stops polling the read
        // side instead of spinning on a permanently-ready EOF.
        Ok(n as usize)
    }
}

impl Write for SessionStream {
    /// The write side: the host stdout, verbatim, with the status
    /// trailer scanned off the stream's end — the trailer's status is
    /// the process's own exit code (the command's own status, the only
    /// status there is), and nothing outlives the exit.
    ///
    /// The scan is a WITHHOLDING scan across rounds. The guest sends
    /// the magic and the status byte as separate packets (two write(2)s
    /// in the guest), and the bridge's rounds split at the guest's own
    /// packet boundaries — a per-round "deliver everything that does not
    /// match" scan LEAKED the parts (MEASURED: `sandal -- uname -a`
    /// printed the whole 16-byte magic to the terminal, and the
    /// leftover `\n\0` left the terminal mangled, before the status
    /// round exited the process). Now every round withholds the longest
    /// suffix that could be the trailer's START — a prefix of the
    /// magic — and delivers the rest: a real trailer's bytes stay
    /// withheld until the status byte completes it (the exit fires, and
    /// not one of them was ever printed), and a false positive —
    /// legitimate output that happens to end with a magic prefix — is
    /// released the next round, one round late, never lost.
    ///
    /// The STREAMING CONTRACT (this exact shape is load-bearing): the
    /// ONLY state this stream keeps is the ≤17-byte withheld tail; the
    /// bridge's outbox is the single backlog. One raw write(2), the
    /// EXACT accepted count returned, and — the part the first cut got
    /// wrong — that count counts BUF bytes only: the tail's bytes go
    /// out first, unpaid, because the round that withheld them already
    /// reported them. An internal window that copied the undelivered
    /// bytes instead made the bridge re-send the full outbox every
    /// round while the window grew by the same bytes again — each round
    /// re-wrote the same prefix over the terminal: the flashing pane
    /// (MEASURED: an 83 KB redraw looped at ~18k rounds/s, the frame
    /// hash never repeating).
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // The scan window: the withheld tail ++ this round's bytes — a
        // temporary; nothing here is stored.
        let mut scan = Vec::with_capacity(self.tail.len() + buf.len());
        scan.extend_from_slice(&self.tail);
        scan.extend_from_slice(buf);
        // The completed trailer at the scan's end: everything before it
        // is the session's output (the withholding rounds held it back),
        // then the exit.
        if scan.len() > TRAILER_MAGIC.len() {
            let at = scan.len() - TRAILER_MAGIC.len() - 1;
            if scan[at..at + TRAILER_MAGIC.len()] == *TRAILER_MAGIC {
                let status = scan[at + TRAILER_MAGIC.len()];

                if at > 0 {
                    // Best-effort: the exit below ends the process
                    // anyway; the pre-trailer output lands as far as
                    // the pty takes it.
                    let _ = write_stdout_exact(&scan, at);
                }
                // The exit diagnostic: the NON-INTERACTIVE path only.
                // There the failing command's own output never becomes
                // visible (the guest drops most of it before it ever
                // posts), and the silent exit was the measured bug — the
                // VMM names the failure. An interactive session named
                // its own failure at the source (the shell's own `not
                // found` line, in the terminal), and the diagnostic
                // would misattribute the status to the session command
                // — which ran (MEASURED: `sandal -- sh` + a typo'd
                // command inside produced "the workload command `sh`
                // was not found").
                if !self.interactive {
                    crate::vm::diagnose_session_exit(
                        status as i32,
                        &[String::from_utf8_lossy(&self.command).into_owned()],
                    );
                }
                if std::env::var_os("SANDAL_DEBUG_TIMING").is_some() {
                    eprintln!(
                        "BOOT_TIMING trailer_scan_exit: {:?}",
                        crate::vm::BOOT_T0.get().map(|t| t.elapsed())
                    );
                }
                std::process::exit(status as i32);
            }
        }
        // No trailer: withhold the longest suffix that could be its
        // start (a prefix of the magic) and deliver the rest — the
        // previously withheld bytes go out now (the magic did not
        // continue there: they were legitimate output, one round late).
        let mut withhold = 0;
        for prefix in 1..=TRAILER_MAGIC.len() {
            if scan.ends_with(&TRAILER_MAGIC[..prefix]) {
                withhold = prefix;
            }
        }
        let deliver = scan.len() - withhold;
        if deliver == 0 {
            return Ok(0);
        }
        // ONE raw write, exact count. The accepted bytes consume the
        // tail first (already reported delivered by the round that
        // withheld them — writing them again must not charge this
        // round's outbox); the rest consume BUF from its front, and
        // that count is what the bridge drains from the outbox. A full
        // pane pty returns WouldBlock with nothing accepted — the tail
        // and the outbox both stay put, and the bridge parks on
        // stdout's own POLLOUT.
        let n = write_stdout_exact(&scan, deliver)?;
        if n <= self.tail.len() {
            // Only withheld bytes went out (or none): no outbox
            // progress to report.
            self.tail = self.tail[n..].to_vec();
            return Ok(0);
        }
        self.tail.clear();
        Ok(n - self.tail.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // The bytes go to the pty through raw write(2) — no userspace
        // buffering to flush.
        Ok(())
    }
}

/// One raw write(2) of `data[..len]` to the host stdout; returns the
/// exact count the kernel accepted. Nonblocking stdout (the pane pty
/// fills under a burst) returns WouldBlock with nothing consumed — the
/// caller keeps its buffers and the bridge parks on stdout's own
/// POLLOUT. A partial accept returns the prefix; the caller loops.
fn write_stdout_exact(data: &[u8], len: usize) -> std::io::Result<usize> {
    loop {
        let n = unsafe { libc::write(1, data.as_ptr().cast(), len as _) };
        if n >= 0 {
            return Ok(n as usize);
        }
        let err = std::io::Error::last_os_error();
        if err.kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        return Err(err);
    }
}

impl HostStream for SessionStream {
    fn shutdown_both(&self) {
        // The host stdio is not ours to shut down (the harness owns it);
        // EOF on the read side is the honest signal. libc's windows
        // surface has no shutdown — the handles were never socketed.
        #[cfg(unix)]
        unsafe {
            let _ = libc::shutdown(0, libc::SHUT_RDWR);
        }
    }

    fn as_raw_fd(&self) -> i32 {
        // The poll side: the host stdin (the read side).
        0
    }

    fn write_fd(&self) -> Option<i32> {
        // The poll side for the outbox: the host STDOUT — a different
        // fd than the read side, and (dup'd descriptions aside) its own
        // writability. See the trait note: polling the read fd for
        // POLLOUT woke the round forever while stdout stayed blocked.
        Some(1)
    }

    fn eof_is_hangup(&self) -> bool {
        // The session's stdin ending is "no more input" — the command
        // keeps running and its output keeps flowing (the measured
        // `sandal -- cmd </dev/null` hang was an EOF-turned-RST).
        false
    }
}
