//! ARM64 ELF builder macro DSL.
//!
//! Instruction-level macros eliminate `e.emit(fn(...))` boilerplate,
//! and high-level macros abstract common syscall patterns.
//! All macros expand before const evaluation — zero runtime overhead.
//!
//! Register arguments use ARM64-style names (`x0`–`x30`, `SP`, `XZR`)
//! resolved at compile time via the [`reg!`] pattern-matching macro.

// ── Register name → number mapping ──────────────────────────────────────

/// Map ARM64 register names to their numeric encoding.
/// Used internally by instruction macros — register arguments are
/// captured as `:tt` and resolved via `reg!()` at expansion time.
macro_rules! reg {
    (x0) => {
        0
    };
    (x1) => {
        1
    };
    (x2) => {
        2
    };
    (x3) => {
        3
    };
    (x4) => {
        4
    };
    (x5) => {
        5
    };
    (x6) => {
        6
    };
    (x7) => {
        7
    };
    (x8) => {
        8
    };
    (x9) => {
        9
    };
    (x10) => {
        10
    };
    (x11) => {
        11
    };
    (x12) => {
        12
    };
    (x13) => {
        13
    };
    (x14) => {
        14
    };
    (x15) => {
        15
    };
    (x16) => {
        16
    };
    (x17) => {
        17
    };
    (x18) => {
        18
    };
    (x19) => {
        19
    };
    (x20) => {
        20
    };
    (x21) => {
        21
    };
    (x22) => {
        22
    };
    (x23) => {
        23
    };
    (x24) => {
        24
    };
    (x25) => {
        25
    };
    (x26) => {
        26
    };
    (x27) => {
        27
    };
    (x28) => {
        28
    };
    (x29) => {
        29
    };
    (x30) => {
        30
    };
    (SP) => {
        31
    };
    (XZR) => {
        31
    };
}

// ── Instruction-level macros ────────────────────────────────────────────
// Register arguments are `:tt`, immediates/offsets are `:expr`.

/// `BRK #imm` — breakpoint / hypercall.
macro_rules! brk {
    ($e:expr, $imm:expr) => {
        $e.emit(brk($imm))
    };
}

/// `SVC #0` — supervisor call.
macro_rules! svc {
    ($e:expr) => {
        $e.emit(svc0())
    };
}

/// `MOV Xd, Xm` — register move (64-bit).
macro_rules! mov {
    ($e:expr, $rd:tt, $rm:tt) => {
        $e.emit(mov_x(reg!($rd), reg!($rm)))
    };
}

/// `MOVZ Xd, #imm` — zero-extend immediate (64-bit).
macro_rules! movz {
    ($e:expr, $rd:tt, $imm:expr) => {
        $e.emit(movz_x(reg!($rd), $imm))
    };
}

/// `MOVN Xd, #imm` — bitwise NOT immediate (64-bit).
macro_rules! movn {
    ($e:expr, $rd:tt, $imm:expr) => {
        $e.emit(movn_x(reg!($rd), $imm))
    };
}

/// `MOVK Xd, #imm, LSL #shift` — keep with shift (64-bit).
macro_rules! movk {
    ($e:expr, $rd:tt, $imm:expr, $shift:expr) => {
        $e.emit(movk_x(reg!($rd), $imm, $shift))
    };
}

/// `MOVZ Wd, #imm` — zero-extend immediate (32-bit).
macro_rules! movz_w {
    ($e:expr, $rd:tt, $imm:expr) => {
        $e.emit(movz_w(reg!($rd), $imm))
    };
}

/// `MOVK Wd, #imm, LSL #shift` — keep with shift (32-bit).
macro_rules! movk_w {
    ($e:expr, $rd:tt, $imm:expr, $shift:expr) => {
        $e.emit(movk_w(reg!($rd), $imm, $shift))
    };
}

/// `ADD Xd, Xn, #imm12`.
macro_rules! add {
    ($e:expr, $rd:tt, $rn:tt, $imm:expr) => {
        $e.emit(add_x_imm(reg!($rd), reg!($rn), $imm))
    };
}

/// `ADD Xd, Xn, Xm`.
macro_rules! add_reg {
    ($e:expr, $rd:tt, $rn:tt, $rm:tt) => {
        $e.emit(add_x_reg(reg!($rd), reg!($rn), reg!($rm)))
    };
}

/// `SUB Xd, Xn, #imm12`.
macro_rules! sub {
    ($e:expr, $rd:tt, $rn:tt, $imm:expr) => {
        $e.emit(sub_x_imm(reg!($rd), reg!($rn), $imm))
    };
}

/// `SUB Xd, Xn, Xm`.
macro_rules! sub_reg {
    ($e:expr, $rd:tt, $rn:tt, $rm:tt) => {
        $e.emit(sub_x_reg(reg!($rd), reg!($rn), reg!($rm)))
    };
}

/// `SUB Xd|SP, Xn|SP, Xm` — subtract register, SP-safe.
///
/// Uses the extended-register encoding (UXTX) so register 31 is
/// treated as SP, unlike the shifted-register `sub_reg!` where 31 = XZR.
macro_rules! sub_sp_reg {
    ($e:expr, $rd:tt, $rn:tt, $rm:tt) => {
        $e.emit(sub_sp_reg(reg!($rd), reg!($rn), reg!($rm)))
    };
}

/// `BIC Xd, Xn, Xm` — bit clear: `Xd = Xn AND NOT Xm`.
macro_rules! bic_reg {
    ($e:expr, $rd:tt, $rn:tt, $rm:tt) => {
        $e.emit(bic_x_reg(reg!($rd), reg!($rn), reg!($rm)))
    };
}

/// `CMP Xn, #imm12`.
macro_rules! cmp {
    ($e:expr, $rn:tt, $imm:expr) => {
        $e.emit(cmp_x_imm(reg!($rn), $imm))
    };
}

/// `CMP Xn, Xm`.
macro_rules! cmp_reg {
    ($e:expr, $rn:tt, $rm:tt) => {
        $e.emit(cmp_x_reg(reg!($rn), reg!($rm)))
    };
}

/// `LDR Xt, [Xn, #off]` — 64-bit load.
macro_rules! ldr {
    ($e:expr, $rt:tt, $rn:tt, $off:expr) => {
        $e.emit(ldr_x(reg!($rt), reg!($rn), $off))
    };
}

/// `LDR Wt, [Xn, #off]` — 32-bit load.
macro_rules! ldr_w {
    ($e:expr, $rt:tt, $rn:tt, $off:expr) => {
        $e.emit(ldr_w(reg!($rt), reg!($rn), $off))
    };
}

/// `LDR Xt, [SP, #off]`.
macro_rules! ldr_sp {
    ($e:expr, $rt:tt, $off:expr) => {
        $e.emit(ldr_x_sp(reg!($rt), $off))
    };
}

/// `LDRB Wt, [Xn, #off]`.
macro_rules! ldrb {
    ($e:expr, $rt:tt, $rn:tt, $off:expr) => {
        $e.emit(ldrb_w(reg!($rt), reg!($rn), $off))
    };
}

/// `LDRB Wt, [Xn], #1` — post-increment.
macro_rules! ldrb_post {
    ($e:expr, $rt:tt, $rn:tt) => {
        $e.emit(ldrb_w_post(reg!($rt), reg!($rn)))
    };
}

/// `STR Xt, [Xn, #off]` — 64-bit store.
macro_rules! str_x {
    ($e:expr, $rt:tt, $rn:tt, $off:expr) => {
        $e.emit(str_x(reg!($rt), reg!($rn), $off))
    };
}

/// `STR Wt, [Xn, #off]` — 32-bit store.
macro_rules! str_w {
    ($e:expr, $rt:tt, $rn:tt, $off:expr) => {
        $e.emit(str_w(reg!($rt), reg!($rn), $off))
    };
}

/// `STRB Wt, [Xn], #1` — post-increment.
macro_rules! strb_post {
    ($e:expr, $rt:tt, $rn:tt) => {
        $e.emit(strb_w_post(reg!($rt), reg!($rn)))
    };
}

/// `STRH Wt, [Xn, #off]` — 16-bit store.
macro_rules! strh {
    ($e:expr, $rt:tt, $rn:tt, $off:expr) => {
        $e.emit(strh_w(reg!($rt), reg!($rn), $off))
    };
}

/// `UBFX Xd, Xn, #lsb, #width`.
macro_rules! ubfx {
    ($e:expr, $rd:tt, $rn:tt, $lsb:expr, $width:expr) => {
        $e.emit(ubfx_x(reg!($rd), reg!($rn), $lsb, $width))
    };
}

/// `UDIV Xd, Xn, Xm`.
macro_rules! udiv {
    ($e:expr, $rd:tt, $rn:tt, $rm:tt) => {
        $e.emit(udiv_x(reg!($rd), reg!($rn), reg!($rm)))
    };
}

/// `MSUB Xd, Xn, Xm, Xa` — `Xd = Xa - Xn * Xm`.
macro_rules! msub {
    ($e:expr, $rd:tt, $rn:tt, $rm:tt, $ra:tt) => {
        $e.emit(msub_x(reg!($rd), reg!($rn), reg!($rm), reg!($ra)))
    };
}

/// `LSL Xd, Xn, #shift`.
macro_rules! lsl {
    ($e:expr, $rd:tt, $rn:tt, $imm:expr) => {
        $e.emit(lsl_x(reg!($rd), reg!($rn), $imm))
    };
}

// ── Data section ────────────────────────────────────────────────────────

/// `ADR Xd, <data>` — load PC-relative data address.
macro_rules! adr {
    ($e:expr, $rd:tt, $data:expr) => {
        $e.emit_adr_data(reg!($rd), $data)
    };
}

/// Batch-register null-terminated C strings in the ELF data section.
macro_rules! strings {
    ($e:expr, $($name:ident = $val:expr),* $(,)?) => {
        $(let $name = $e.emit_cstring($val);)*
    };
}

// ── Control flow ────────────────────────────────────────────────────────

/// Emit a backward branch to a previously-recorded code offset.
macro_rules! b_back {
    ($e:expr, $br:ident, $target:expr) => {
        $e.emit($br(ElfBuilder::branch_offset($e.offset(), $target)))
    };
    ($e:expr, $br:ident, $rt:tt, $target:expr) => {
        $e.emit($br(
            reg!($rt),
            ElfBuilder::branch_offset($e.offset(), $target),
        ))
    };
}

/// Patch a forward-branch placeholder to the current offset.
macro_rules! patch_forward {
    ($e:expr, $ph:expr, $br:ident) => {
        $e.patch($ph, $br(ElfBuilder::branch_offset($ph, $e.offset())))
    };
    ($e:expr, $ph:expr, $br:ident, $rt:tt) => {
        $e.patch(
            $ph,
            $br(reg!($rt), ElfBuilder::branch_offset($ph, $e.offset())),
        )
    };
}

// ── Syscall helpers ─────────────────────────────────────────────────────

/// Emit syscall: `MOVZ X8, #NR; SVC #0`.
macro_rules! syscall {
    ($e:expr, $nr:expr) => {{
        movz!($e, x8, $nr);
        svc!($e);
    }};
}

// ── High-level Linux operations ─────────────────────────────────────────

/// `mount(source, target, fstype [, flags [, data_reg]])`.
macro_rules! mount {
    ($e:expr, $src:expr, $tgt:expr, $fs:expr) => {
        mount!($e, $src, $tgt, $fs, 0)
    };
    ($e:expr, $src:expr, $tgt:expr, $fs:expr, $flags:expr) => {{
        adr!($e, x0, $src);
        adr!($e, x1, $tgt);
        adr!($e, x2, $fs);
        movz!($e, x3, $flags);
        movz!($e, x4, 0);
        syscall!($e, $crate::elf::linux::nr::MOUNT);
    }};
    ($e:expr, $src:expr, $tgt:expr, $fs:expr, $flags:expr, $data:tt) => {{
        adr!($e, x0, $src);
        adr!($e, x1, $tgt);
        adr!($e, x2, $fs);
        movz!($e, x3, $flags);
        mov!($e, x4, $data);
        syscall!($e, $crate::elf::linux::nr::MOUNT);
    }};
}

/// `mount --bind source target`.
macro_rules! mount_bind {
    ($e:expr, $src:expr, $tgt:expr) => {{
        adr!($e, x0, $src);
        adr!($e, x1, $tgt);
        movz!($e, x2, 0);
        movz!($e, x3, $crate::elf::linux::MS_BIND);
        movz!($e, x4, 0);
        syscall!($e, $crate::elf::linux::nr::MOUNT);
    }};
}

/// `mkdir path` — mkdirat(AT_FDCWD, path, 0755).
macro_rules! mkdir {
    ($e:expr, $path:expr) => {{
        movn!($e, x0, $crate::elf::linux::AT_FDCWD_NEG);
        adr!($e, x1, $path);
        movz!($e, x2, 0x1ED);
        syscall!($e, $crate::elf::linux::nr::MKDIRAT);
    }};
}

/// `mkdir_under parent, child` — openat(parent) + mkdirat(fd, child, 0755) + close.
macro_rules! mkdir_under {
    ($e:expr, $parent:expr, $child:expr) => {{
        openat!($e, $parent, $crate::elf::linux::O_RDONLY);
        mov!($e, x11, x0); // save fd for close
        adr!($e, x1, $child);
        movz!($e, x2, 0x1ED);
        syscall!($e, $crate::elf::linux::nr::MKDIRAT);
        close!($e, x11);
    }};
}

/// `cd path` — chdir(path).
macro_rules! chdir {
    ($e:expr, $path:expr) => {{
        adr!($e, x0, $path);
        syscall!($e, $crate::elf::linux::nr::CHDIR);
    }};
}

/// `pivot_root new_root put_old`.
macro_rules! pivot_root {
    ($e:expr, $new:expr, $old:expr) => {{
        adr!($e, x0, $new);
        adr!($e, x1, $old);
        syscall!($e, $crate::elf::linux::nr::PIVOT_ROOT);
    }};
}

/// `openat(AT_FDCWD, path, flags [, mode])` — result in x0.
///
/// Path variants:
///   - `openat!(e, str_offset, flags)` — path from ELF data section (adr)
///   - `openat!(e, [SP, off], flags)` — path pointer loaded from stack slot
///   - `openat!(e, SP, flags)` — path buffer at SP
macro_rules! openat {
    ($e:expr, [SP, $off:expr], $flags:expr) => {{
        movn!($e, x0, $crate::elf::linux::AT_FDCWD_NEG);
        ldr_sp!($e, x1, $off);
        movz!($e, x2, $flags);
        syscall!($e, $crate::elf::linux::nr::OPENAT);
    }};
    ($e:expr, SP, $flags:expr) => {{
        movn!($e, x0, $crate::elf::linux::AT_FDCWD_NEG);
        add!($e, x1, SP, 0);
        movz!($e, x2, $flags);
        syscall!($e, $crate::elf::linux::nr::OPENAT);
    }};
    ($e:expr, $path:expr, $flags:expr) => {{
        movn!($e, x0, $crate::elf::linux::AT_FDCWD_NEG);
        adr!($e, x1, $path);
        movz!($e, x2, $flags);
        syscall!($e, $crate::elf::linux::nr::OPENAT);
    }};
    ($e:expr, $path:expr, $flags:expr, $mode:expr) => {{
        movn!($e, x0, $crate::elf::linux::AT_FDCWD_NEG);
        adr!($e, x1, $path);
        movz!($e, x2, $flags);
        movz!($e, x3, $mode);
        syscall!($e, $crate::elf::linux::nr::OPENAT);
    }};
}

/// `close(fd_register)`.
macro_rules! close {
    ($e:expr, $reg:tt) => {{
        mov!($e, x0, $reg);
        syscall!($e, $crate::elf::linux::nr::CLOSE);
    }};
}

/// `exit(code)`.
macro_rules! exit {
    ($e:expr, $code:expr) => {{
        movz!($e, x0, $code);
        syscall!($e, $crate::elf::linux::nr::EXIT);
    }};
}

/// `ioctl(fd_reg, cmd, &stack_buf)` — buffer at SP.
/// `ioctl(fd_reg, cmd, val)` — explicit immediate value.
macro_rules! ioctl {
    ($e:expr, $fd:tt, $cmd:expr) => {{
        mov!($e, x0, $fd);
        movz!($e, x1, $cmd);
        add!($e, x2, SP, 0);
        syscall!($e, $crate::elf::linux::nr::IOCTL);
    }};
    ($e:expr, $fd:tt, $cmd:expr, $val:expr) => {{
        mov!($e, x0, $fd);
        movz!($e, x1, $cmd);
        movz!($e, x2, $val);
        syscall!($e, $crate::elf::linux::nr::IOCTL);
    }};
}

/// `setsid()` — create a new session.
macro_rules! setsid {
    ($e:expr) => {{
        syscall!($e, $crate::elf::linux::nr::SETSID);
    }};
}

/// `dup3(oldfd_reg, newfd_imm)` — duplicate fd, flags=0.
macro_rules! dup3 {
    ($e:expr, $oldfd:tt, $newfd:expr) => {{
        mov!($e, x0, $oldfd);
        movz!($e, x1, $newfd);
        movz!($e, x2, 0);
        syscall!($e, $crate::elf::linux::nr::DUP3);
    }};
}

/// `fork()` — clone(SIGCHLD, 0, 0, 0, 0), child pid in x0.
macro_rules! fork {
    ($e:expr) => {{
        movz!($e, x0, $crate::elf::linux::SIGCHLD);
        movz!($e, x1, 0);
        movz!($e, x2, 0);
        movz!($e, x3, 0);
        movz!($e, x4, 0);
        syscall!($e, $crate::elf::linux::nr::CLONE);
    }};
}

/// `wait4(pid_reg)` — wait for child, status written to [SP].
macro_rules! wait4 {
    ($e:expr, $pid:tt) => {{
        mov!($e, x0, $pid);
        add!($e, x1, SP, 0);
        movz!($e, x2, 0);
        movz!($e, x3, 0);
        syscall!($e, $crate::elf::linux::nr::WAIT4);
    }};
}

/// `reboot()` — LINUX_REBOOT_CMD_POWER_OFF.
macro_rules! reboot {
    ($e:expr) => {{
        movz!($e, x0, 0xDEAD);
        movk!($e, x0, 0xFEE1, 16);
        movz!($e, x1, 0x1969);
        movk!($e, x1, 0x2812, 16);
        movz!($e, x2, 0xFEDC);
        movk!($e, x2, 0x4321, 16);
        movz!($e, x3, 0);
        syscall!($e, $crate::elf::linux::nr::REBOOT);
    }};
}

/// `execve(path_reg, envp_reg)` — argv assumed at SP.
/// `execve(path_off, argv_off, envp_reg)` — path and argv at SP offsets.
/// `execve(skip N)` — exec argv[N] with remaining args, envp from stack layout.
macro_rules! execve {
    ($e:expr, $path:tt, $envp:tt) => {{
        mov!($e, x0, $path);
        add!($e, x1, SP, 0);
        mov!($e, x2, $envp);
        syscall!($e, $crate::elf::linux::nr::EXECVE);
    }};
    ($e:expr, SP + $path_off:expr, SP + $argv_off:expr, $envp:tt) => {{
        add!($e, x0, SP, $path_off);
        add!($e, x1, SP, $argv_off);
        mov!($e, x2, $envp);
        syscall!($e, $crate::elf::linux::nr::EXECVE);
    }};
    ($e:expr, skip $n:expr) => {{
        let _off: u32 = ($n + 1) * 8;
        ldr_sp!($e, x0, _off); // path = argv[N]
        add!($e, x4, SP, 0); // x4 = SP
        add!($e, x1, x4, _off); // argv_ptr = &argv[N]
        ldr_sp!($e, x3, 0); // argc
        add!($e, x3, x3, 2_u32); // argc + 2 (argv[] + NULL)
        lsl!($e, x3, x3, 3); // * 8
        add_reg!($e, x2, x4, x3); // envp
        syscall!($e, $crate::elf::linux::nr::EXECVE);
    }};
}

/// `socket(domain, type)` — result fd in x0.
macro_rules! socket {
    ($e:expr, $domain:expr, $type:expr) => {{
        movz!($e, x0, $domain);
        movz!($e, x1, $type);
        movz!($e, x2, 0);
        syscall!($e, $crate::elf::linux::nr::SOCKET);
    }};
}

/// `finit_module(fd_reg, params_str)` — load kernel module.
macro_rules! finit_module {
    ($e:expr, $fd:tt, $params:expr) => {{
        mov!($e, x0, $fd);
        adr!($e, x1, $params);
        movz!($e, x2, 0);
        syscall!($e, $crate::elf::linux::nr::FINIT_MODULE);
    }};
}

/// `uname(base_reg, offset)` — result at base+offset.
macro_rules! uname {
    ($e:expr, $base:tt, $off:expr) => {{
        add!($e, x0, $base, $off);
        syscall!($e, $crate::elf::linux::nr::UNAME);
    }};
}

/// `clock_settime(clockid)` — timespec pointer at SP.
macro_rules! clock_settime {
    ($e:expr, $clockid:expr) => {{
        movz!($e, x0, $clockid);
        add!($e, x1, SP, 0);
        syscall!($e, $crate::elf::linux::nr::CLOCK_SETTIME);
    }};
}

/// `sys_write(fd, buf, len)` — write data to fd.
///
/// Forms:
///   `sys_write!(e, 2, s_label, 20)`  — immediate fd, static string, immediate len
///   `sys_write!(e, x11, s_label, 20)` — register fd, static string, immediate len
///   `sys_write!(e, 2, x27)`           — immediate fd, register buf, x2 already set
macro_rules! sys_write {
    ($e:expr, $fd:literal, $buf:tt) => {{
        movz!($e, x0, $fd);
        mov!($e, x1, $buf);
        syscall!($e, $crate::elf::linux::nr::WRITE);
    }};
    ($e:expr, $fd:literal, $buf:expr, $len:expr) => {{
        movz!($e, x0, $fd);
        adr!($e, x1, $buf);
        movz!($e, x2, $len);
        syscall!($e, $crate::elf::linux::nr::WRITE);
    }};
    ($e:expr, $fd:tt, $buf:expr, $len:expr) => {{
        mov!($e, x0, $fd);
        adr!($e, x1, $buf);
        movz!($e, x2, $len);
        syscall!($e, $crate::elf::linux::nr::WRITE);
    }};
}

/// `strlen(src_reg)` — compute length of null-terminated string into x2.
/// Clobbers x1, x3.
macro_rules! strlen {
    ($e:expr, $src:tt) => {{
        mov!($e, x1, $src);
        let _loop = $e.offset();
        ldrb_post!($e, x3, x1);
        b_back!($e, cbnz, x3, _loop);
        sub_reg!($e, x2, x1, $src);
        sub!($e, x2, x2, 1);
    }};
}

/// Zero `N` 8-byte words at SP.
macro_rules! zero_stack {
    ($e:expr, $words:expr) => {{
        let mut _i: u32 = 0;
        while _i < $words {
            str_x!($e, XZR, SP, _i * 8);
            _i += 1;
        }
    }};
}
