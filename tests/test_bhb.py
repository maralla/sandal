#!/usr/bin/env python3
"""The aarch64 SMCCC conduit: the guest's spectre-BHB mitigation engages.

The sandbox (macOS/HVF) answers the guest kernel's SMCCC architectural
calls (VERSION, ARCH_FEATURES, ARCH_WORKAROUND_1) from `handle_hvc`.
With them, a kernel built with
CONFIG_MITIGATE_SPECTRE_BRANCH_HISTORY=y applies its branch-history
hardening instead of disabling it at probe time ("the firmware does not
implement the workaround").

This test only runs where it can: macOS on aarch64 (the HVF path). The
Linux/KVM aarch64 path handles non-PSCI HVCs in-kernel and cannot forward
SMCCC to userspace — there the mitigation stays runtime-disabled by
design. Everywhere else the test self-skips.

Usage (from the repo root, after `make`):
    uv run python tests/test_bhb.py
"""

import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, host_can_run_vm, test_main  # noqa: E402

BHB_SYSFS = "/sys/devices/system/cpu/vulnerabilities/spectre_bhb"


def main() -> None:
    machine = sys.platform
    if machine != "darwin" or os.uname().machine.lower() not in ("aarch64", "arm64"):
        print("test_bhb: SKIP: the SMCCC conduit is the macOS/HVF path only")
        return
    if not host_can_run_vm():
        print("test_bhb: SKIP: the host cannot run the guest")
        return

    vm = Vm()
    try:
        vm.boot("bhb boot")
        # The kernel probed the firmware over HVC at boot: the sandbox's
        # SMCCC answers made the spectre-BHB hardening engage. A probe
        # crash here means the conduit broke the boot.
        vm.run("echo SMCCC_ALIVE; echo ALIVE_DONE", "ALIVE_DONE")
        vm.run(
            f"cat {BHB_SYSFS}; echo BHB_READ_DONE",
            "BHB_READ_DONE",
        )
        report = vm.buf.decode(errors="replace")
    finally:
        vm.close()

    if "SMCCC_ALIVE" not in report:
        raise AssertionError(f"bhb: the session broke over the SMCCC conduit: {report[-200:]!r}")
    line = next(
        (l for l in report.splitlines() if "spectre_bhb" in l and ":" in l),
        None,
    )
    if line is None:
        raise AssertionError(f"bhb: no spectre_bhb sysfs entry: {report[-200:]!r}")
    if "Vulnerable" in line:
        raise AssertionError(
            f"bhb: the spectre-BHB mitigation did not engage: {line.strip()!r}"
        )
    print(f"test_bhb: the spectre-BHB mitigation engages ({line.strip()}): OK", flush=True)


if __name__ == "__main__":
    sys.exit(test_main("bhb", main))
