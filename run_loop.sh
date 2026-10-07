#!/usr/bin/env bash
#
# Fleet entry point for the loop stress harness of the OCaml binding:
# builds the utility's dune target (a no-op when it is up to date;
# libitb3.so and the binding library are assumed built by build.sh) and
# execs it with every argument passed through.
#
# The build output is captured rather than discarded: dune reports its
# progress and any warning on stderr, and a redirect of stdout alone
# would let those lines join the utility's own output. Nothing is
# printed unless the build fails, in which case everything it said is.
#
# Usage:
#   ./run_loop.sh --duration 2m --shape both

set -eu
set -o pipefail

cd "$(dirname "$0")"

if command -v opam >/dev/null 2>&1; then
    eval "$(opam env 2>/dev/null)" || true
fi

if ! build_output="$(dune build --no-print-directory loop/main.exe 2>&1)"; then
    printf '%s\n' "$build_output" >&2
    exit 1
fi

exec ./_build/default/loop/main.exe "$@"
