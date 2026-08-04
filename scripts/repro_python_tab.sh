#!/usr/bin/env bash
# Interactive virtio-console / readline / uv stress harness for sandal.
#
# Gate (hang_issue_attempts.md): --no-cache only; never SANDAL_USE_CACHE=1 for this harness.
# Run only after `make` so release/sandal matches src. Wall-clock: always `timeout 60` on the script.
# Example:
#   make -j
#   timeout 60 env REPRO_FAIL_FAST=1 REPRO_FAST_STRESS=1 SANDAL_TRACE_CONSOLE_IO=1 SANDAL_TRACE_FILE=./sandal_trace.log \
#     ./scripts/repro_python_tab.sh --fail-fast --trace-console-io --trace-file ./sandal_trace.log --exit-cycle
# Global flags may appear before or after the subcommand (stripped from any position).
#
# Env (common):
#   EX_SANDAL          path to sandal (default: $REPO_ROOT/target/release/sandal)
#   EX_DISK            overlay size MB (default: 64)
#   EX_LAYER / REPRO_LAYER   override path to uv+python layer (default: $REPO_ROOT/uv-python3.14.layer)
#   REPRO_FAIL_FAST=1  shorter expect timeouts (pair with REPRO_FAST_STRESS for ~60s gates)
#   SANDAL_TRACE_CONSOLE_IO, SANDAL_TRACE_CONSOLE_DEEP, SANDAL_TRACE_FILE — forwarded to the child
#
# See hang_issue_attempts.md for trace field meanings.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$REPO_ROOT"

: "${EX_SANDAL:=$REPO_ROOT/target/release/sandal}"
: "${EX_DISK:=64}"
: "${EX_LAYER:=${REPRO_LAYER:-$REPO_ROOT/uv-python3.14.layer}}"

if [[ ! -f "${EX_LAYER}" ]]; then
	echo >&2 "repro: missing layer file: ${EX_LAYER}"
	echo >&2 "  Place uv-python3.14.layer in the repo root, or set EX_LAYER / REPRO_LAYER."
	exit 2
fi

: "${EX_GAP_MIN:=40}"
: "${EX_GAP_MAX:=220}"
: "${EX_TYPE_MIN:=18}"
: "${EX_TYPE_MAX:=95}"
: "${EX_PRE_TAB_MIN:=40}"
: "${EX_PRE_TAB_MAX:=180}"
: "${EX_PRE_CTRLC_MIN:=55}"
: "${EX_PRE_CTRLC_MAX:=190}"
: "${EX_PTY_ROWS:=40}"
: "${EX_PTY_COLS:=120}"
: "${EX_LOG_USER:=0}"
: "${REPRO_EXPECT_NOTTYCOPY:=0}"

TRACE_CONSOLE_IO=0
TRACE_CONSOLE_DEEP=0
TRACE_ANOMALY=0
TRACE_FILE=""
FAIL_FAST=0
GLOBAL_REPRO_ARGS=()

strip_global_flags() {
	unset _REPRO_OUT; _REPRO_OUT=()
	while [[ $# -gt 0 ]]; do
		case "$1" in
		--trace-console-io) TRACE_CONSOLE_IO=1 ;;
		--trace-console-deep) TRACE_CONSOLE_DEEP=1 ;;
		--trace-anomaly) TRACE_ANOMALY=1 ;;
		--trace-file)
			shift
			TRACE_FILE=${1:-}
			[[ -n "$TRACE_FILE" ]] || {
				echo >&2 "--trace-file needs a path"
				exit 2
			}
			;;
		--fail-fast) FAIL_FAST=1 ;;
		*) _REPRO_OUT+=("$1") ;;
		esac
		shift
	done
		# Use explicit index loop instead of [@] expansion for bash 3.2 compat
		GLOBAL_REPRO_ARGS=()
		for (( _ri = 0; _ri < ${#_REPRO_OUT[@]}; _ri++ )); do
			GLOBAL_REPRO_ARGS+=("${_REPRO_OUT[$_ri]}")
		done
}

strip_global_flags "$@"
set --
for (( _ri = 0; _ri < ${#GLOBAL_REPRO_ARGS[@]}; _ri++ )); do
	set -- "$@" "${GLOBAL_REPRO_ARGS[$_ri]}"
done

if [[ "$FAIL_FAST" == 1 ]]; then
	export REPRO_FAIL_FAST=1
fi
if [[ "$TRACE_CONSOLE_IO" == 1 ]]; then
	export SANDAL_TRACE_CONSOLE_IO=1
fi
if [[ "$TRACE_CONSOLE_DEEP" == 1 ]]; then
	export SANDAL_TRACE_CONSOLE_DEEP=1
fi
if [[ "$TRACE_ANOMALY" == 1 ]]; then
	export SANDAL_TRACE_ANOMALY=1
fi
if [[ -n "$TRACE_FILE" ]]; then
	export SANDAL_TRACE_FILE="$TRACE_FILE"
fi

apply_fail_fast_defaults() {
	if [[ "${REPRO_FAIL_FAST:-}" != "1" ]]; then
		return 0
	fi
	: "${EXPECT_BOOT_TIMEOUT:=180}"
	: "${PYTHON_RESTART_TIMEOUT:=95}"
	: "${TAB_DEADLINE_SEC:=45}"
	: "${EOF_DEADLINE_SEC:=55}"
	: "${REPRO_EXIT_FIRST_WAIT:=20}"
	: "${REPRO_SUBSHELL_WAIT:=22}"
	: "${REPRO_ENSURE_SHELL_TIMEOUT:=12}"
}

apply_exit_cycle_fail_fast() {
	if [[ "${REPRO_FAIL_FAST:-}" != "1" ]]; then
		return 0
	fi
	: "${EXPECT_BOOT_TIMEOUT:=28}"
	: "${PYTHON_RESTART_TIMEOUT:=28}"
	: "${REPRO_EXIT_FIRST_WAIT:=8}"
	: "${REPRO_SUBSHELL_WAIT:=10}"
	: "${REPRO_ENSURE_SHELL_TIMEOUT:=8}"
	: "${EX_EXIT_REPL_SETTLE_MS:=5500}"
	export EXPECT_BOOT_TIMEOUT PYTHON_RESTART_TIMEOUT REPRO_EXIT_FIRST_WAIT
	export REPRO_SUBSHELL_WAIT REPRO_ENSURE_SHELL_TIMEOUT EX_EXIT_REPL_SETTLE_MS
	export REPRO_FAST_STRESS=1
}

repro_dump_trace_on_failure() {
	local xit=$1
	if [[ -n "${SANDAL_TRACE_FILE:-}" && -f "${SANDAL_TRACE_FILE}" ]]; then
		echo >&2 "repro: trace tail (${SANDAL_TRACE_FILE}, exit $xit):"
		tail -n 80 "${SANDAL_TRACE_FILE}" >&2 || true
	fi
}

run_expect_once() {
	local attempts=$1
	apply_fail_fast_defaults
	: "${EXPECT_BOOT_TIMEOUT:=180}"
	: "${TAB_DEADLINE_SEC:=45}"
	: "${EOF_DEADLINE_SEC:=55}"
	: "${REPRO_EXIT_FIRST_WAIT:=20}"
	export EXPECT_BOOT_TIMEOUT TAB_DEADLINE_SEC EOF_DEADLINE_SEC REPRO_EXIT_FIRST_WAIT
	export EX_SANDAL EX_DISK EX_LAYER
	export EX_GAP_MIN EX_GAP_MAX EX_TYPE_MIN EX_TYPE_MAX
	export EX_PRE_TAB_MIN EX_PRE_TAB_MAX EX_PRE_CTRLC_MIN EX_PRE_CTRLC_MAX
	export EX_PTY_ROWS EX_PTY_COLS EX_LOG_USER
	export REPRO_EXPECT_NOTTYCOPY="${REPRO_EXPECT_NOTTYCOPY:-0}"
	export EX_ATTEMPTS=$attempts
	export EX_PY_RESTART="${PYTHON_RESTART_TIMEOUT:-95}"
	export EX_EXIT_REPL_SETTLE_MS="${EX_EXIT_REPL_SETTLE_MS:-0}"
	export EX_SUBSHELL_WAIT="${REPRO_SUBSHELL_WAIT:-22}"
	export EX_ENSURE_SHELL_TIMEOUT="${REPRO_ENSURE_SHELL_TIMEOUT:-12}"
	export EX_REPRO_PROFILE="${EX_REPRO_PROFILE:-full}"

	local xit=0
	expect <<'EXPECT_EOF' || xit=$?
set timeout $env(EXPECT_BOOT_TIMEOUT)

proc rand_ms { a b } {
	expr {int($a + round(rand() * ($b - $a)))}
}

proc maybe_long_think {} {
	global env
	if {![info exists env(REPRO_FAST_STRESS)] || $env(REPRO_FAST_STRESS) != "1"} {
		after [rand_ms 200 900]
	}
}

proc repro_stable_pty {} {
	global env
	catch { stty rows $env(EX_PTY_ROWS) cols $env(EX_PTY_COLS) }
	catch { stty -ixon -ixoff }
	match_max [expr {512 * 1024}]
}

proc type_human_line { text } {
	global env
	set t0 [expr {int($env(EX_TYPE_MIN))}]
	set t1 [expr {int($env(EX_TYPE_MAX))}]
	foreach ch [split $text {}] {
		send -- $ch
		after [rand_ms $t0 $t1]
	}
}

proc send_force_exit_python_repl {} {
	global env
	send -- "\x15"
	set t0 [expr {int($env(EX_TYPE_MIN))}]
	set t1 [expr {int($env(EX_TYPE_MAX))}]
	after [rand_ms $t0 $t1]
	send -- "exit()\r"
}

proc send_uv_run_python {} {
	global env
	maybe_long_think
	set g0 [expr {int($env(EX_GAP_MIN))}]
	set g1 [expr {int($env(EX_GAP_MAX))}]
	after [rand_ms $g0 $g1]
	send -- "uv run python -u\r"
}

proc ensure_shell_ready {} {
	global env
	send -- "stty sane 2>/dev/null\r"
	after 150
	set t [expr {int($env(EX_ENSURE_SHELL_TIMEOUT))}]
	if {$t < 3} { set t 3 }
	set timeout $t
	set tok [clock milliseconds]
	send -- "echo SANDAL_REPRO_SHELL_OK_$tok\r"
	expect {
		-re "SANDAL_REPRO_SHELL_OK_$tok" { return 1 }
		timeout { return 0 }
		eof { puts stderr "eof during shell readiness check"; exit 1 }
	}
}

proc phase_gap {} {
	global env
	set g0 [expr {int($env(EX_GAP_MIN))}]
	set g1 [expr {int($env(EX_GAP_MAX))}]
	after [rand_ms $g0 $g1]
}

proc send_import_pl_tab {} {
	global env
	maybe_long_think
	type_human_line "import pl"
	set p0 [expr {int($env(EX_PRE_TAB_MIN))}]
	set p1 [expr {int($env(EX_PRE_TAB_MAX))}]
	after [rand_ms $p0 $p1]
	send -- "\t"
}

repro_stable_pty

if {$env(REPRO_EXPECT_NOTTYCOPY) == "1"} {
	spawn -noecho -nottycopy $env(EX_SANDAL) --no-cache --disk-size $env(EX_DISK) --layer $env(EX_LAYER) -- sh
} else {
	spawn -noecho $env(EX_SANDAL) --no-cache --disk-size $env(EX_DISK) --layer $env(EX_LAYER) -- sh
}

if {$env(EX_LOG_USER) == "0"} {
	log_user 0
}

set py_restart [expr {int($env(EX_PY_RESTART))}]
set attempts [expr {int($env(EX_ATTEMPTS))}]

expect {
	# Root ash is often `/ # ` with a DSR `\033[6n` (or similar) appended — `/[\s#]*$` never matches.
	-re {/[\s#]*(?:\x1b|\r|\n|$)} { }
	-re {>>>} { }
	timeout { puts stderr "timeout: boot / shell prompt"; exit 1 }
	eof { puts stderr "sandal exited during boot"; exit 1 }
}

for {set i 1} {$i <= $attempts} {incr i} {
	if {$i % 2 == 1} {
		if {$env(EX_LOG_USER) == "0"} {
			puts stderr "attempt $i / $attempts: uv run python (Tab / readline phase)"
		} else {
			puts stderr "attempt $i / $attempts: uv run python"
		}
		send_uv_run_python
		set timeout $py_restart
		expect {
			-re {>>>} { }
			timeout { puts stderr "timeout: no Python >>>"; exit 1 }
			eof { puts stderr "sandal exited mid-test"; exit 1 }
		}
		type_human_line "import pl"
		set p0 [expr {int($env(EX_PRE_TAB_MIN))}]
		set p1 [expr {int($env(EX_PRE_TAB_MAX))}]
		after [rand_ms $p0 $p1]
		send -- "\t"
		set timeout [expr {int($env(TAB_DEADLINE_SEC))}]
		expect {
			-re {>>>} { }
			timeout { puts stderr "timeout: Tab/readline"; exit 1 }
			eof { puts stderr "eof after Tab"; exit 1 }
		}
		send -- "\r"
		set timeout [expr {int($env(EOF_DEADLINE_SEC))}]
		expect {
			-re {>>>} { }
			timeout { puts stderr "timeout: after Tab newline"; exit 1 }
			eof { puts stderr "eof after Tab newline"; exit 1 }
		}
	} else {
		if {$env(EX_REPRO_PROFILE) == "exit_cycle"} {
			puts stderr "attempt $i / $attempts: exit/os._exit, uv run python (no Ctrl-C)"
		} else {
			puts stderr "attempt $i / $attempts: os._exit(0), uv run python"
		}
		send_force_exit_python_repl
		set em [expr {int($env(EX_EXIT_REPL_SETTLE_MS))}]
		if {$em > 0} {
			set settle $em
		} else {
			set settle [expr {max(13000, int($env(REPRO_EXIT_FIRST_WAIT)) * 1000)}]
		}
		after $settle
		set sw [expr {int($env(EX_SUBSHELL_WAIT))}]
		if {$sw < 8} { set sw 8 }
		set timeout $sw
		expect {
			-re {\r?\n.*?/\s*#\s} { }
			timeout {
				puts stderr "warn: no ash \`/ #\` seen after exit+settle (attempt $i); continuing to shell probe"
			}
			eof { puts stderr "eof after exit()+settle"; exit 1 }
		}
		if {![ensure_shell_ready]} {
			puts stderr "warn: no shell after exit(); os._exit once (attempt $i)"
			send_force_exit_python_repl
			after 500
			if {![ensure_shell_ready]} {
				puts stderr "HANG: no shell after REPL exit (attempt $i)"
				exit 2
			}
		}
		if {$env(EX_REPRO_PROFILE) != "exit_cycle"} {
			if {![ensure_shell_ready]} {
				puts stderr "timeout: shell not stable before uv run python (attempt $i)"
				exit 1
			}
		}
		after 200
		send_uv_run_python
		set timeout $py_restart
		expect {
			-re {>>>} { }
			timeout { puts stderr "timeout: no >>> after uv run python (attempt $i)"; exit 1 }
			eof { puts stderr "eof before Python prompt"; exit 1 }
		}
	}
	if {$i < $attempts} {
		phase_gap
	}
}

if {$attempts > 1} {
	puts stderr "completed $attempts phases with no hang (repeat many runs before treating hang as fixed)"
}
exit 0
EXPECT_EOF

	if [[ "$xit" -ne 0 ]]; then
		repro_dump_trace_on_failure "$xit"
	fi
	return "$xit"
}

cmd_expect() {
	run_expect_once 1
}

cmd_stress() {
	local n="${1:-200}"
	run_expect_once "$n"
}

cmd_stress_repeat() {
	local phases="${1:-4}"
	local reps="${2:-25}"
	local i
	for ((i = 1; i <= reps; i++)); do
		echo >&2 "repro: stress-repeat $i/$reps (${phases} phases, abort on first fail)"
		run_expect_once "$phases" || return $?
	done
	echo >&2 "repro: stress-repeat all $reps passed"
}

cmd_exit_cycle() {
	apply_exit_cycle_fail_fast
	export EX_REPRO_PROFILE=exit_cycle
	run_expect_once 2
}

cmd_tab_only() {
	export EX_REPRO_PROFILE=tab_only
	run_expect_once 1
}

usage() {
	cat <<'U'
Usage:
  scripts/repro_python_tab.sh [global flags] <command>

Global flags (any position before subcommand):
  --fail-fast
  --trace-console-io
  --trace-console-deep
  --trace-anomaly
  --trace-file PATH

Commands:
  expect | cmd_expect              single phase (default)
  stress [N]                       N alternating phases (default 200)
  stress-repeat [phases reps]
  exit-cycle | --exit-cycle        one VM: uv → Python → exit → second uv (no Tab)
  tab-only | --tab-only

Wrap with timeout 60 for agent gates (see AGENTS.md).
U
}

main() {
	if [[ $# -eq 0 ]]; then
		cmd_expect
		return
	fi
	case "$1" in
	-h | --help | help)
		usage
		;;
	expect | cmd_expect)
		cmd_expect
		;;
	stress | --stress)
		shift
		cmd_stress "${1:-200}"
		;;
	stress-repeat | --stress-repeat)
		shift
		cmd_stress_repeat "${1:-4}" "${2:-25}"
		;;
	exit-cycle | --exit-cycle)
		cmd_exit_cycle
		;;
	tab-only | --tab-only)
		cmd_tab_only
		;;
	*)
		echo >&2 "unknown command: $1"
		usage
		exit 2
		;;
	esac
}

main "$@"
