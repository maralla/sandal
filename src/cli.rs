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

    /// Kernel image path [default: vmlinux-sandal]
    #[arg(short = 'k', long = "kernel")]
    pub kernel: Option<PathBuf>,

    /// Initrd image path
    #[arg(short = 'i', long = "initrd")]
    pub initrd: Option<PathBuf>,

    /// Root filesystem ext2 image [default: rootfs.ext2]
    #[arg(short = 'r', long = "rootfs")]
    pub rootfs: Option<PathBuf>,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Disable snapshot caching (always boot from scratch)
    #[arg(long = "no-cache")]
    pub no_cache: bool,
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
