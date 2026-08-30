#!/usr/bin/env bash
#
# run_tests.sh -- one-step test runner for the OCaml binding. Builds
# libitb.so and the dune project via build.sh, points ITB_LIBITB_PATH
# at the freshly-built shared library, then runs the alcotest suite.
# Positional arguments are forwarded to the alcotest binary (e.g. a
# single group via `./run_tests.sh test message`).
#
# Usage:
#   ./run_tests.sh                 # full suite
#   ./run_tests.sh test stream     # one group

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

if command -v opam >/dev/null 2>&1; then
    eval "$(opam env 2>/dev/null)" || true
fi

if [ "$#" -gt 0 ]; then
    exec dune exec --no-print-directory test/test_itb.exe -- "$@"
fi
# --force so a cached earlier run is re-executed against the
# freshly-built libitb.so (the shared library is not a dune
# dependency, so dune's runtest cache would otherwise skip it).
exec dune test --no-print-directory --force
