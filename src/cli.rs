use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sandal",
    about = "Ultra-lightweight Linux VM for macOS",
    long_about = "Run Linux commands in an ephemeral, ultra-fast VM with controlled filesystem and network access"
)]
pub struct Args {
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

    /// Kernel image path [default: kernels/vmlinux]
    #[arg(short = 'k', long = "kernel")]
    pub kernel: Option<PathBuf>,

    /// Initrd image path
    #[arg(short = 'i', long = "initrd")]
    pub initrd: Option<PathBuf>,

    /// Root filesystem directory (packed as initramfs) [default: rootfs/]
    #[arg(short = 'r', long = "rootfs")]
    pub rootfs: Option<PathBuf>,

    /// Verbose output
    #[arg(short = 'v', long = "verbose")]
    pub verbose: bool,
}
