mod cli;
mod hypervisor;
mod vm;
mod virtio;
mod net;
mod devicetree;
mod initramfs;
mod unet;
mod ext2;

use anyhow::Result;
use clap::Parser;
use cli::Args;

fn main() -> Result<()> {
    let args = Args::parse();

    env_logger::Builder::new()
        .filter_level(if args.verbose {
            log::LevelFilter::Debug
        } else {
            log::LevelFilter::Warn
        })
        .format_timestamp(None)
        .format_target(false)
        .init();

    // Ensure we're running on macOS
    #[cfg(not(target_os = "macos"))]
    {
        anyhow::bail!("sandal only supports macOS");
    }
    
    #[cfg(target_os = "macos")]
    {
        vm::run(args)?;
    }
    
    Ok(())
}
