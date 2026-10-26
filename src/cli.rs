use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sandal",
    about = "Ultra-lightweight Linux VM for macOS",
    long_about = "Run Linux commands in an ephemeral, ultra-fast VM with controlled filesystem and network access"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Run a command inside the VM
    Run(RunArgs),
    /// Pack a host directory into an ext2 rootfs image
    Pack(PackArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct RunArgs {
    /// Command to run inside the VM. Optional with --port: a VM without
    /// a command is the pure command daemon — it serves every command
    /// through the port and never quits on its own; the guest's native
    /// power commands (poweroff, halt, reboot — they signal PID 1, and
    /// the accept loop IS PID 1) shut it down cleanly. Without --port
    /// the command is required.
    #[arg(required = false)]
    pub command: Vec<String>,

    /// Shared directories from host (format: host_path:guest_path)
    #[arg(short = 's', long = "share", value_name = "HOST:GUEST")]
    pub shared_dirs: Vec<String>,

    /// Disable network access (networking is enabled by default)
    #[arg(long = "no-network")]
    pub no_network: bool,

    /// Allowed protocols (comma-separated: http,https)
    #[arg(long = "protocols", default_value = "http,https")]
    pub protocols: String,

    /// Allowed hosts whitelist (comma-separated)
    #[arg(long = "allowed-hosts")]
    pub allowed_hosts: Option<String>,

    /// Memory size in MB
    #[arg(short = 'm', long = "memory", default_value = "256")]
    pub memory: usize,

    /// Kernel image path [default: embedded kernel in release builds
    /// (make dist), else vmlinux-sandal-<arch> next to the binary]
    #[arg(short = 'k', long = "kernel")]
    pub kernel: Option<PathBuf>,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Root filesystem ext2 image [default: built-in rootfs]
    #[arg(short = 'r', long = "rootfs")]
    pub rootfs: Option<PathBuf>,

    /// Extra writable disk size in MB (creates /dev/vdb with overlayfs).
    /// Can be combined with --layer: layers are pre-populated into the disk.
    #[arg(long = "disk-size", value_name = "MB")]
    pub disk_size: Option<usize>,

    /// Load a .layer file (gzip-compressed tar) into the overlay filesystem.
    /// Can be specified multiple times; layers are applied in order.
    /// When combined with --disk-size, layers are injected into the ext2 disk.
    #[arg(long = "layer", value_name = "PATH")]
    pub layers: Vec<PathBuf>,

    /// Enable the virtio-vsock device: the VMM listens on ADDR:PORT
    /// (ADDR defaults to 127.0.0.1; 0.0.0.0 exposes it) and bridges every
    /// connection through vsock to the guest's /bin/vsockd — the command
    /// execution line. Each connection carries a 9-byte header
    /// ({mode, rows, cols, cmd_len}, little-endian) plus the command
    /// line; the command's output comes back verbatim and the stream
    /// ends with a 17-byte status trailer (16 magic bytes + the exit
    /// status). Connections are concurrent: the guest forks per
    /// connection.
    ///
    /// With a command, the VM ALSO runs that command as its session
    /// (`sandal --port 8022 -- tmux`), and the VM's life is the
    /// session's. Without one, the VM is the pure command daemon: it
    /// boots, serves the port, and quits only on the guest's native
    /// power commands (poweroff/halt/reboot — they signal PID 1, and
    /// the accept loop IS PID 1) or when the host kills it.
    #[arg(long = "port", value_name = "[ADDR:]PORT")]
    pub port: Option<String>,
}

#[derive(Parser, Debug, Clone)]
pub struct PackArgs {
    /// Source directory to pack
    pub dir: PathBuf,

    /// Output ext2 image path
    #[arg(short = 'o', long = "output", default_value = "rootfs.ext2")]
    pub output: PathBuf,
}

/// Legacy Args type alias — used by vm.rs and main.rs.
/// This is identical to RunArgs.
pub type Args = RunArgs;
