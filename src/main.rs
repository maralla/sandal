mod cli;
mod devicetree;
mod ext2;
mod hypervisor;
mod initramfs;
mod net;
mod snapshot;
mod unet;
mod virtio;
mod vm;

use anyhow::Result;
use clap::Parser;
use cli::{Args, Cli, Command, PackArgs};

/// Check if a valid snapshot exists and try to restore from it.
/// Returns None if no snapshot is available, Some(Ok(())) if restore succeeded
/// (note: process exits inside), or Some(Err) if restore failed.
fn try_snapshot_restore(args: &Args) -> Option<Result<()>> {
    let t0 = std::time::Instant::now();

    // We need to read the kernel to compute the fingerprint.
    let kernel_path = match &args.kernel {
        Some(p) => p.clone(),
        None => vm::resolve_data_path("vmlinux-sandal")?,
    };
    let kernel_data = std::fs::read(&kernel_path).ok()?;
    log::debug!(
        "[bench] read kernel: {:.2}ms",
        t0.elapsed().as_secs_f64() * 1000.0
    );

    // Resolve rootfs path
    let default_rootfs = if args.rootfs.is_none() {
        vm::resolve_data_path("rootfs.ext2")
    } else {
        None
    };
    let rootfs_path = args.rootfs.as_ref().or(default_rootfs.as_ref());

    let network_enabled = !args.no_network;

    // Compute rootfs fingerprint from file content (stable hash, only reads 8KB)
    let t1 = std::time::Instant::now();
    let rootfs_fp = rootfs_path
        .map(|p| snapshot::hash_file_content(p))
        .unwrap_or(0);
    log::debug!(
        "[bench] hash rootfs: {:.2}ms",
        t1.elapsed().as_secs_f64() * 1000.0
    );

    let fingerprint = snapshot::compute_fingerprint(
        &kernel_data,
        rootfs_fp,
        args.memory,
        network_enabled,
        &args.shared_dirs,
    );

    let snap_path = snapshot::snapshot_path(fingerprint).ok()?;
    if !snap_path.exists() {
        return None;
    }

    log::debug!(
        "[bench] fingerprint check: {:.2}ms total from start",
        t0.elapsed().as_secs_f64() * 1000.0
    );
    log::info!("Found snapshot: {}", snap_path.display());
    Some(vm::run_from_snapshot(args, &snap_path, fingerprint))
}

fn run_pack(pack_args: &PackArgs) -> Result<()> {
    if !pack_args.dir.is_dir() {
        anyhow::bail!("Source path {:?} is not a directory", pack_args.dir);
    }

    eprintln!("Packing {:?} into {:?}...", pack_args.dir, pack_args.output);

    let image = ext2::pack_directory(&pack_args.dir)?;

    std::fs::write(&pack_args.output, &image)?;
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
            if let Some(snap_result) = try_snapshot_restore(&args) {
                match snap_result {
                    Ok(()) => return Ok(()),
                    Err(e) => {
                        log::debug!("Snapshot restore failed, falling back to full boot: {e}");
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
