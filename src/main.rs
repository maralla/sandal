mod cli;
mod devicetree;
#[macro_use]
mod elf;
mod ext2;
mod gic;
mod hypervisor;
mod init;
mod initramfs;
mod net;
mod rootfs;
mod tar;
mod unet;
mod virtio;
mod vm;
mod vmm_trace;

use anyhow::Result;
use clap::Parser;
use cli::{Args, Cli, Command, PackArgs};
use std::fs;

fn run_pack(pack_args: &PackArgs) -> Result<()> {
    if !pack_args.dir.is_dir() {
        anyhow::bail!("Source path {:?} is not a directory", pack_args.dir);
    }

    eprintln!("Packing {:?} into {:?}...", pack_args.dir, pack_args.output);

    let image = ext2::pack_directory(&pack_args.dir)?;

    fs::write(&pack_args.output, &image)?;
    eprintln!(
        "Wrote {} bytes ({} KB) to {:?}",
        image.len(),
        image.len() / 1024,
        pack_args.output,
    );

    Ok(())
}

fn run_vm(args: Args) -> Result<()> {
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
        let code = vm::run(args)?;
        std::process::exit(code);
    }

    #[allow(unreachable_code)]
    Ok(())
}

fn main() -> Result<()> {
    // Try parsing with subcommands first. If that fails (e.g. `sandal echo hello`
    // where `echo` isn't a known subcommand), fall back to parsing the entire
    // command line as RunArgs for backward compatibility.
    match Cli::try_parse() {
        Ok(cli) => match cli.command {
            Some(Command::Run(args)) => run_vm(args),
            Some(Command::Pack(pack_args)) => run_pack(&pack_args),
            None => {
                // `sandal` with no args — show help
                let _ = Cli::parse(); // This will print help and exit
                Ok(())
            }
        },
        Err(_) => {
            // Failed to parse as subcommand — try as bare RunArgs
            // (backward compat: `sandal echo hello` == `sandal run echo hello`)
            let args = Args::try_parse()
                .map_err(|e| {
                    // If this also fails, show the original CLI help
                    e.exit();
                })
                .unwrap();

            run_vm(args)
        }
    }
}
