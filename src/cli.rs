use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "sandal",
    about = "Ultra-lightweight Linux VM for macOS",
    long_about = "Run Linux commands in an ephemeral, ultra-fast VM with controlled filesystem and network access"
)]
pub struct Args {
    /// Command to run inside the VM (optional with --port)
    #[arg(required = false)]
    pub command: Vec<String>,

    /// Execute a script file in the VM; the VM exits with its status
    #[arg(long = "script", value_name = "FILE")]
    pub script: Option<PathBuf>,

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

    /// Kernel image path [default: the embedded release kernel]
    #[arg(short = 'k', long = "kernel")]
    pub kernel: Option<PathBuf>,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,

    /// Root filesystem ext2 image [default: built-in rootfs]
    #[arg(short = 'r', long = "rootfs")]
    pub rootfs: Option<PathBuf>,

    /// Writable data-disk size in MB (the overlay upper)
    #[arg(long = "disk-size", value_name = "MB")]
    pub disk_size: Option<usize>,

    /// Load a .layer file into the overlay; repeatable, applied in order
    #[arg(long = "layer", value_name = "PATH")]
    pub layers: Vec<PathBuf>,

    // The protocol (the 9-byte header, the 17-byte trailer, the fork
    // per connection) is documented in vsock_host.rs; the help line is
    // the contract.
    /// Serve the command execution line on ADDR:PORT
    #[arg(long = "port", value_name = "[ADDR:]PORT")]
    pub port: Option<String>,

    /// Pack a host directory into an ext2 rootfs image (the rootfs
    /// build's tool; not a VM action).
    #[command(subcommand)]
    pub action: Option<Command>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    /// Pack a host directory into an ext2 rootfs image
    #[command(hide = true)]
    Pack(PackArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct PackArgs {
    /// Source directory to pack
    pub dir: PathBuf,

    /// Output ext2 image path
    #[arg(short = 'o', long = "output", default_value = "rootfs.ext2")]
    pub output: PathBuf,

    /// Compress the image with zstd (the built-in rootfs format).
    #[arg(long = "zstd")]
    pub zstd: bool,
}
