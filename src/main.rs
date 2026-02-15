mod cli;
mod devicetree;
#[macro_use]
mod elf;
mod ext2;
mod hypervisor;
mod init;
mod initramfs;
mod net;
mod rootfs;
mod snapshot;
mod tar;
mod unet;
mod virtio;
mod vm;

use anyhow::Result;
use clap::Parser;
use cli::{Args, Cli, Command, PackArgs};
use std::fs;
use std::path::PathBuf;
use std::time::Instant;

/// Check if a valid snapshot exists and try to restore from it.
/// Returns `(Option<Result<()>>, Option<PathBuf>)`:
/// - First element: None if no snapshot found, Some(Ok/Err) if attempted.
/// - Second element: snapshot path if one was found (for cleanup on failure).
fn try_snapshot_restore(args: &Args) -> (Option<Result<()>>, Option<PathBuf>) {
    let t0 = Instant::now();

    // Resolve kernel and rootfs paths.
    let kernel_path = match &args.kernel {
        Some(p) => p.clone(),
        None => match vm::resolve_data_path("vmlinux-sandal") {
            Some(p) => p,
            None => return (None, None),
        },
    };
    let default_rootfs = if args.rootfs.is_none() {
        vm::resolve_data_path("rootfs.ext2")
    } else {
        None
    };
    let rootfs_path = args.rootfs.as_ref().or(default_rootfs.as_ref());

    let network_enabled = !args.no_network;

    // Fingerprint from file content (reads only 8KB per file, not the
    // full kernel).  Reliable across copies, git checkouts, etc.
    let kernel_fp = snapshot::hash_file_content(&kernel_path);
    let rootfs_fp = if let Some(p) = rootfs_path {
        snapshot::hash_file_content(p)
    } else {
        // No external rootfs — use built-in rootfs fingerprint.
        // Hash the compressed bytes directly (stable, no decompression needed).
        snapshot::hash_bytes(rootfs::BUILTIN_ROOTFS_GZ)
    };

    let fingerprint =
        snapshot::compute_fingerprint(kernel_fp, rootfs_fp, args.memory, network_enabled);

    let snap_path = match snapshot::snapshot_path(fingerprint) {
        Ok(p) => p,
        Err(_) => return (None, None),
    };
    if !snap_path.exists() {
        return (None, None);
    }

    log::debug!(
        "[bench] fingerprint check: {:.2}ms total from start",
        t0.elapsed().as_secs_f64() * 1000.0
    );
    log::info!("Found snapshot: {}", snap_path.display());
    let result = vm::run_from_snapshot(args, &snap_path, fingerprint);
    (Some(result), Some(snap_path))
}

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
        // Try snapshot restore fast path first
        if !args.no_cache {
            let (snap_result, snap_path) = try_snapshot_restore(&args);
            if let Some(result) = snap_result {
                match result {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        log::debug!("Snapshot restore failed, falling back to full boot: {e}");
                        // Delete the stale/invalid snapshot so the next cold
                        // boot creates a fresh one.
                        if let Some(p) = snap_path {
                            log::debug!("Removing stale snapshot: {}", p.display());
                            let _ = fs::remove_file(&p);
                        }
                    }
                }
            }
        }

        vm::run(args)?;
    }

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
