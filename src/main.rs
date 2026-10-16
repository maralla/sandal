// The VMM runs the host terminal with output processing disabled (guest
// escape sequences must pass verbatim), which also stops the terminal from
// translating `\n` to `\r\n` — so the VMM's own diagnostics would print as
// a staircase (each line keeping the previous line's column). Shadow
// `eprintln!` for the whole crate with the explicit translation instead:
// exactly what the terminal would have done under ONLCR, and ONLCR never
// spared escape sequences either, so this is semantics preserving.
macro_rules! eprintln {
    ($($arg:tt)*) => {{
        let text = ::std::format!("{}\n", ::std::format_args!($($arg)*));
        let bytes = $crate::virtio::onlcr(text.into_bytes());
        let _ = ::std::io::Write::write_all(&mut ::std::io::stderr(), &bytes);
    }};
}

mod cli;
#[cfg(target_arch = "aarch64")]
mod devicetree;
#[macro_use]
mod elf;
mod ext2;
mod hypervisor;
mod initramfs;
mod irqs;
#[cfg(not(target_os = "windows"))]
mod net;
mod rootfs;
mod tar;
#[cfg(not(target_os = "windows"))]
pub mod unet;
mod virtio;
mod vm;
mod vmm_trace;
mod zchunk;

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
        // The guest console needs OPOST disabled on the shared host tty, so a
        // log line ending in a bare `\n` does not return the cursor to column
        // 0 and the next line is indented by the previous line's width.
        // Emit CRLF here; an extra CR on a normal tty renders as nothing.
        .format_suffix("\r\n")
        .init();

    // Check we're running on a supported host.
    #[cfg(target_os = "windows")]
    {
        if !args.no_network {
            eprintln!("sandal: networking is not yet supported on Windows hosts — running without");
            // The run flag lives on `args`; the WHP boot path forces it off.
            // (Handled in `Vmm::new`; nothing to do here.)
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux", target_os = "windows"))]
    {
        let code = vm::run(args)?;
        if std::env::var_os("SANDAL_DEBUG_TIMING").is_some() {
            eprintln!(
                "BOOT_TIMING teardown_done: {:?}",
                crate::vm::BOOT_T0.get().map(|t| t.elapsed()).unwrap_or_default()
            );
        }
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
