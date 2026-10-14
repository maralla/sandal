/* The crafted `portagent` x86_64 guest helper: the session agent.
 *
 * Bridges the interactive session between the virtio-console host device
 * port (/dev/virtio-ports/vport0p1) and a guest pty:
 *
 *   - the session runs on the pty SLAVE — a real tty: job control,
 *     signals, line editing and the tty's own echo, all with real
 *     semantics (a pty slave is claimable as a controlling terminal,
 *     unlike the console device);
 *   - the agent pumps whole buffers between the port fd and the pty
 *     MASTER — the port's per-exit rate instead of the console device's
 *     round trip per output line;
 *   - the terminal geometry comes from the command line (the VMM's
 *     advertised window, known at boot) and, later, from resize
 *     records the VMM injects into the port input stream — see the
 *     record scan below.
 *
 * The parent is the reaper: the session's exit status is forwarded (the
 * init script's exit marker), 128+signal for signal deaths (the shell
 * convention).
 *
 * usage: portagent <port> <rows> <cols> <command> [args...]
 * exit:  120 = the port open failed, 121 = the pty setup failed,
 *        125 = the session exec failed, otherwise the session's status.
 *
 * Freestanding: no libc — raw x86_64 Linux syscalls (the stubs below).
 * Built by build.rs into a static ELF (see the portagent.rs loader and
 * the ext2 injection); the init script falls back to the plain console
 * session (ctty) when this helper is missing or the pty setup fails.
 */

typedef long syslong;
typedef unsigned long sysulong;

/* One syscall, six arguments (the x86_64 kernel ABI: rdi, rsi, rdx,
 * r10, r8, r9). rcx/r11 are clobbered by the instruction itself. */
static syslong syscall6(syslong n, syslong a1, syslong a2, syslong a3,
                        syslong a4, syslong a5, syslong a6)
{
    register syslong r10 __asm__("r10") = a4;
    register syslong r8 __asm__("r8") = a5;
    register syslong r9 __asm__("r9") = a6;
    syslong ret;
    __asm__ volatile("syscall"
                     : "=a"(ret)
                     : "a"(n), "D"(a1), "S"(a2), "d"(a3),
                       "r"(r10), "r"(r8), "r"(r9)
                     : "rcx", "r11", "memory");
    return ret;
}

/* Syscall numbers (x86_64) and UAPI constants. */
#define SYS_read      0
#define SYS_write     1
#define SYS_open      2
#define SYS_close     3
#define SYS_poll      7
#define SYS_ioctl     16
#define SYS_clone     56
#define SYS_execve    59
#define SYS_exit      60
#define SYS_wait4     61
#define SYS_kill      62
#define SYS_setsid    112
#define SYS_dup3      292
#define SYS_nanosleep 35

#define O_RDWR      2
#define SIGCHLD     17
#define SIGKILL     9
#define TIOCSCTTY   0x540E
#define TIOCSWINSZ  0x5414
#define TIOCSPTLCK  0x40045431 /* unlockpt() when the arg is 0 */
#define TIOCGPTPEER 0x5441     /* the pty slave fd, from the master */
#define POLLIN      0x001

static syslong xopen(const char *path, syslong flags)
{
    return syscall6(SYS_open, (syslong)path, flags, 0, 0, 0, 0);
}
static syslong xclose(syslong fd)
{
    return syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
}
static syslong xioctl(syslong fd, syslong cmd, syslong arg)
{
    return syscall6(SYS_ioctl, fd, cmd, arg, 0, 0, 0);
}
static void xexit(syslong code)
{
    syscall6(SYS_exit, code, 0, 0, 0, 0, 0);
    for (;;) { }
}

/* A decimal parse (no libc): the geometry the init script passes on the
 * command line. */
static syslong xatol(const char *s)
{
    syslong v = 0;
    for (; *s >= '0' && *s <= '9'; s++)
        v = v * 10 + (*s - '0');
    return v;
}

/* The pump buffers: SEPARATE — the input path's buffer must never be
 * clobbered by the output path's read (a shared buffer leaked the
 * session's output tail into the input stream, prepending it to the
 * next input line). */
static char in_buf[4096];
static char out_buf[4096];

/* A full transfer, partial writes included. */
static void write_all(syslong fd, const char *buf, syslong len)
{
    syslong off = 0;
    while (off < len) {
        syslong n = syscall6(SYS_write, fd, (syslong)(buf + off), len - off,
                             0, 0, 0);
        if (n <= 0)
            return; /* the fd is gone; the loop's reader decides */
        off += n;
    }
}

/* ── The resize record ────────────────────────────────────────────────
 *
 * The VMM injects one 8-byte record into the port INPUT stream whenever
 * the host window changes:
 *
 *   [u32 magic "RSZ1"][u16 cols][u16 rows]   (little-endian)
 *
 * The bridge strips every whole record out of the stream and applies the
 * size to the pty pair; the kernel then SIGWINCHs the session's
 * foreground process group, so the session (the shell, tmux, editors)
 * re-sizes itself exactly like a real terminal would. This is the only
 * reliable dynamic channel: the virtio config-change path depends on
 * the guest driver's config work actually running, which it does only
 * on its own schedule. */
#define RESIZE_MAGIC   0x315a5352u /* "RSZ1" as the record's LE u32 */
#define RESIZE_REC_LEN 8
#define RESIZE_MAX     4096 /* cols/rows sanity: beyond any real window */

/* Strip every whole record in buf, applying the size. Returns the
 * remaining length (records removed). The record is delivered whole or
 * not at all (the VMM's window gate — see set_resize_record), and it
 * always fits whole in a read (8 bytes vs the 4 KiB buffer), so there
 * is no straddle to carry: a carry keyed on the magic's PREFIX would
 * hold any input that merely ends in 'R' (the DSR cursor reply
 * "\x1b[1;1R"!) and prepend it to the next input line. */
static syslong resize_strip(char *buf, syslong len, syslong master)
{
    syslong r = 0, w = 0;
    while (r < len) {
        if (len - r >= RESIZE_REC_LEN
            && *(unsigned int *)(buf + r) == RESIZE_MAGIC) {
            unsigned short cols = *(unsigned short *)(buf + r + 4);
            unsigned short rows = *(unsigned short *)(buf + r + 6);
            if (cols > 0 && rows > 0 && cols <= RESIZE_MAX
                && rows <= RESIZE_MAX) {
                unsigned short ws[4] = { rows, cols, 0, 0 };
                xioctl(master, TIOCSWINSZ, (syslong)ws);
            }
            r += RESIZE_REC_LEN;
        } else {
            buf[w++] = buf[r++];
        }
    }
    return w;
}

/* The initial stack (System V process startup): [sp]=argc,
 * [sp+8+8i]=argv[i], argv[argc]=NULL, then envp[]. The trampoline hands
 * the original sp to agent_main and aligns the stack. agent_main is a
 * GLOBAL symbol (a local symbol would not resolve at link time), and it
 * is entered by CALL, not JMP: the compiler's frame setup assumes the
 * ABI's call-entry stack state (rsp ≡ 8 mod 16) — a jmp with an
 * aligned rsp leaves every movaps in the frame misaligned and the first
 * one faults. agent_main never returns (xexit parks); the ud2 behind
 * the call is unreachable. */
__asm__(".globl _start, agent_main\n"
        "_start:\n"
        "  mov %rsp, %rdi\n"      /* rdi = the initial stack block */
        "  andq $-16, %rsp\n"     /* 16-aligned before the call (ABI) */
        "  call agent_main\n"
        "  ud2\n");

void agent_main(syslong *sp)
{
    syslong argc = sp[0];
    char **argv = (char **)&sp[1];
    char **envp = (char **)&sp[1 + argc + 1];

    if (argc < 5)
        xexit(126);

    syslong port = xopen(argv[1], O_RDWR);
    if (port < 0)
        xexit(120); /* the transport is gone: the marker forwards it */

    /* The pty pair: open the MASTER, unlock it, then take the SLAVE fd
     * straight from the master (TIOCGPTPEER) — no /dev/pts path lookup,
     * which would resolve in whatever devpts instance the mount happens
     * to be. Ptys are created LOCKED: without the unlock the slave open
     * fails with EIO. O_RDWR: the flags argument IS the peer fd's open
     * flags — 0 (O_RDONLY) would hand the session a write-refused slave
     * and every session write would fail EBADF. */
    syslong master = xopen("/dev/ptmx", O_RDWR);
    if (master < 0)
        xexit(121);
    syslong zero = 0;
    if (xioctl(master, TIOCSPTLCK, (syslong)&zero) < 0)
        xexit(121);
    syslong slave = xioctl(master, TIOCGPTPEER, O_RDWR);
    if (slave < 0)
        xexit(121);

    /* The boot geometry: the VMM's advertised window, passed on the
     * command line (argv[2] = rows, argv[3] = cols) — known at boot,
     * long before any tty exists. The console device's own winsize is
     * NOT a source: it only ever changes when the guest driver's config
     * work runs, which happens on its own schedule or not at all.
     * Applied to the pair before the fork so both sides see it; no
     * session exists yet, so the SIGWINCH the kernel fires lands on
     * nobody. */
    {
        unsigned short ws[4] = {
            (unsigned short)xatol(argv[2]), /* rows */
            (unsigned short)xatol(argv[3]), /* cols */
            0,
            0,
        };
        if (ws[0] > 0 && ws[0] <= RESIZE_MAX && ws[1] > 0
            && ws[1] <= RESIZE_MAX)
            xioctl(master, TIOCSWINSZ, (syslong)ws);
    }

    /* fork: the session (the child) and the bridge (the parent). */
    syslong pid = syscall6(SYS_clone, SIGCHLD, 0, 0, 0, 0, 0);
    if (pid < 0)
        xexit(121);

    if (pid == 0) {
        /* The session: own session, the pty slave as the controlling
         * terminal — a pty slave IS claimable (unlike the console
         * device), so job control and tty signals work. argv[4] is the
         * command path (the session's argv[0]); argv[5..] pass
         * through; envp is preserved. */
        syscall6(SYS_setsid, 0, 0, 0, 0, 0, 0);
        xclose(master);
        xclose(port);
        syscall6(SYS_dup3, slave, 0, 0, 0, 0, 0);
        syscall6(SYS_dup3, slave, 1, 0, 0, 0, 0);
        syscall6(SYS_dup3, slave, 2, 0, 0, 0, 0);
        if (slave > 2)
            xclose(slave);
        xioctl(0, TIOCSCTTY, 1);

        /* exec <command> [args...]; with NO arguments force the shell's
         * interactive mode ("-i"): without it ash reads stdin forever
         * without a prompt. */
        {
            char *nargv[64];
            syslong n = 0;
            nargv[n++] = argv[4];
            if (argc == 5)
                nargv[n++] = "-i";
            for (syslong i = 5; i < argc && n < 63; i++)
                nargv[n++] = argv[i];
            nargv[n] = 0;
            syscall6(SYS_execve, (syslong)argv[4], (syslong)nargv,
                     (syslong)envp, 0, 0, 0);
        }
        xexit(125); /* the exec failed: the marker forwards it */
    }

    /* The bridge: pump whole buffers port <-> pty master. */
    xclose(slave);

    struct pollfd {
        int fd;
        short events;
        short revents;
    };
    struct timespec {
        long tv_sec;
        long tv_nsec;
    } nap = { 0, 100000000 }; /* the paced !host_connected retry: 100 ms */

    for (;;) {
        struct pollfd pfds[2];
        pfds[0].fd = (int)port;
        pfds[0].events = POLLIN;
        pfds[0].revents = 0;
        pfds[1].fd = (int)master;
        pfds[1].events = POLLIN;
        pfds[1].revents = 0;
        syscall6(SYS_poll, (syslong)pfds, 2, -1, 0, 0, 0);

        /* Host input -> the pty (the tty does the echo and line
         * editing). Resize records ride this stream: strip and apply
         * them (see RESIZE_MAGIC). A failed read is the port not yet
         * connected (the control handshake): a paced retry, never a
         * busy loop. */
        if (pfds[0].revents) {
            syslong n = syscall6(SYS_read, port, (syslong)in_buf,
                                 sizeof(in_buf), 0, 0, 0);
            if (n > 0) {
                syslong total = resize_strip(in_buf, n, master);
                if (total > 0)
                    write_all(master, in_buf, total);
            } else {
                syscall6(SYS_nanosleep, (syslong)&nap, 0, 0, 0, 0, 0);
            }
        }

        /* Session output/echo -> the port. A failed read means every
         * slave fd is closed: the session is dead — reap and forward. */
        if (pfds[1].revents) {
            syslong n = syscall6(SYS_read, master, (syslong)out_buf,
                                 sizeof(out_buf), 0, 0, 0);
            if (n > 0)
                write_all(port, out_buf, n);
            else
                break;
        }
    }

    /* The reaper: the session is gone (or its transport is). Forward the
     * status: a signal death (status & 0xff != 0) exits 128+signal (the
     * shell convention); a normal exit forwards status >> 8. */
    syscall6(SYS_kill, pid, SIGKILL, 0, 0, 0, 0);
    syslong status = 0;
    syscall6(SYS_wait4, -1, (syslong)&status, 0, 0, 0, 0);
    syslong code = (status & 0xff) ? 128 + (status & 0xff) : (status >> 8);
    xexit(code);
}
