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
    /// Command to run inside the VM
    #[arg(required = true)]
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

    /// Enable the virtio-vsock device: the VMM listens on
    /// ADDR:PORT (ADDR defaults to 127.0.0.1; 0.0.0.0 exposes it) and
    /// bridges every connection through vsock to the guest's own TCP
    /// loopback — /bin/vsockrelay forwards to sshd there, unmodified.
    /// No port file: the port is the one you named. The guest side
    /// needs sshd listening on its own loopback (apk add openssh;
    /// see tests/test_ssh_relay.py for the proven recipe); auth is
    /// whatever sshd allows — key-only for root by openssh's own
    /// defaults.
    #[arg(long = "ssh-port", value_name = "[ADDR:]PORT")]
    pub ssh_port: Option<String>,
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
