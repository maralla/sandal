# Guest kernel

sandal boots a Linux guest kernel — one per architecture, matching the
host (the guest runs on the hypervisor the host provides: HVF on macOS,
KVM on Linux):

| Host arch | Artifact | Form |
|-----------|----------|------|
| x86_64 | `vmlinux-sandal-x86_64` | Stripped ELF vmlinux carrying the PVH 32-bit entry note — booted directly by the VMM: no firmware, no bootloader |
| arm64 | `vmlinux-sandal-aarch64` | arm64 `Image` |

The VMM resolves the kernel by that exact name from the working directory
or next to the executable (`resolve_data_path` in `src/vm/mod.rs`), so
the file must sit in one of those places under that name.

## Getting a kernel

`make kernel` fetches the prebuilt kernel for the host architecture:

- it downloads `vmlinux-sandal-<arch>` from the
  [sandal-assets](https://github.com/maralla/sandal-assets) release
  (`releases/latest/download/...`),
- verifies the download against the release's `SHA256SUMS`, and
- leaves an already-present file alone — delete it to re-fetch.

`make test` and `make dist` depend on this target.

## Building a kernel

The kernel source, the configs and the build script live in
[sandal-assets](https://github.com/maralla/sandal-assets) — this
repository does not build kernels. To build one manually:

```
git clone git@github.com:maralla/sandal-assets.git
cd sandal-assets

scripts/build-kernel.sh x86_64          # native build (gcc, flex, bison)
scripts/build-kernel.sh aarch64         # native build (aarch64 Linux only)
scripts/build-kernel.sh aarch64 HOST    # cross-build on HOST over SSH (macOS flow)
```

See that repository's README for details. The build writes
`vmlinux-sandal-<arch>` into the sandal-assets root; copy it into this
project's root under the same name to use it.
