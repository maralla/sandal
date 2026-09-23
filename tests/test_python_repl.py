#!/usr/bin/env python3
"""End-to-end test: install uv + CPython in the guest, run the python REPL.

This is the sandbox's core workflow. Verifies:

  * `apk add curl` works (TLS through the user-space netstack),
  * astral.sh's installer runs and puts `uv` on PATH,
  * `uv python install` fetches a CPython build into the overlay,
  * the interactive `python` REPL starts with a working line editor:
    the terminfo entry injected from the host must be present (otherwise
    readline falls back to "dumb terminal" and the REPL is unusable),
    and evaluating an expression must round-trip.

Usage (from the repo root, after `make`):
    uv run python tests/test_python_repl.py
"""

import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from vm_harness import Vm, test_main  # noqa: E402


def main() -> None:
    vm = Vm(["--disk-size", "512"])
    try:
        vm.boot("python-repl")

        def run(cmd: str, marker: str, timeout: float = 420) -> str:
            vm.buf = b""
            vm.send_line(cmd)
            if not vm.wait_for(marker.encode(), 1, timeout):
                raise AssertionError(
                    f"command did not finish: {cmd!r}: "
                    f"{vm.buf.decode('utf-8', 'replace')[-300:]!r}"
                )
            time.sleep(1.0)
            vm.read_more(1.0)
            out = vm.buf.decode("utf-8", "replace")
            return out

        out = run("apk add --no-cache curl 2>&1 | tail -1; echo S1", "S1")
        if "OK:" not in out:
            raise AssertionError(f"apk add curl failed: {out!r}")

        out = run(
            "curl -LsSf https://astral.sh/uv/install.sh | sh 2>&1 | tail -1; echo S2",
            "S2",
            300,
        )
        print("python-repl: uv installed")

        out = run(
            "export PATH=$HOME/.local/bin:$PATH; "
            "uv python install 3.12 2>&1 | tail -1; echo S3",
            "S3",
            480,
        )
        if "cpython" not in out:
            raise AssertionError(f"uv python install failed: {out!r}")
        print("python-repl: cpython installed")

        out = run(
            "export PATH=$HOME/.local/bin:$PATH; uv --version; echo S4", "S4"
        )
        if "uv " not in out:
            raise AssertionError(f"uv not on PATH after install: {out!r}")
        if "No such file" in out:
            raise AssertionError("terminfo entry for TERM=linux missing in the guest")

        # ── The interactive REPL ─────────────────────────────────────────
        vm.buf = b""
        vm.send_line("export PATH=$HOME/.local/bin:$PATH; uv run --no-project python -q")
        time.sleep(6.0)
        vm.read_more(2.0)
        start = vm.buf.decode("utf-8", "replace")
        if ">>>" not in start:
            raise AssertionError(f"python REPL did not start: {start[-200:]!r}")
        if "Cannot read termcap database" in start:
            raise AssertionError(
                "readline fell back to dumb settings — the terminfo entry "
                "for the console is missing"
            )

        vm.send_line("print(6*7)")
        time.sleep(2.0)
        vm.read_more(2.0)
        repl = vm.buf.decode("utf-8", "replace")
        if "\r\n42" not in repl:
            raise AssertionError(f"REPL did not evaluate print(6*7): {repl[-200:]!r}")
        vm.send_line("exit()")
        time.sleep(1.5)
        vm.read_more(1.0)
        if vm.buf.count(b"~ #") == 0:
            raise AssertionError("REPL exit() did not return to the shell")
        print("python-repl: interactive REPL ok (line editor + eval)")
    finally:
        vm.close()


if __name__ == "__main__":
    sys.exit(test_main("python-repl", main))
