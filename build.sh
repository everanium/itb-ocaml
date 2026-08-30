#!/usr/bin/env bash
#
# build.sh -- one-step build for the OCaml binding: builds libitb.so
# from the Go tree, then compiles the dune project (library, tests,
# bench, eitb). Prerequisites (Go, OCaml, opam with ctypes /
# ctypes-foreign / alcotest, dune) must be installed separately; see
# README.md "Prerequisites" section.
#
# Usage:
#   ./build.sh             # default build (full asm stack)
#   ./build.sh --noitbasm  # opt out of ITB's chain-absorb asm
#                          # (use on hosts without AVX-512+VL)

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

TAGS=()
case "${1:-}" in
    --noitbasm) TAGS=(-tags=noitbasm); shift;;
    -h|--help)  echo "usage: $0 [--noitbasm]"; exit 0;;
    "")         ;;
    *)          echo "unknown option: $1" >&2; exit 2;;
esac

cd "$REPO_ROOT"
echo "==> building libitb.so${TAGS:+ (with ${TAGS[*]})}"
go build -trimpath "${TAGS[@]}" -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared

cd "$REPO_ROOT/bindings/ocaml"
if command -v opam >/dev/null 2>&1; then
    eval "$(opam env 2>/dev/null)" || true
fi

echo "==> building the dune project (library, tests, bench, eitb)"
dune build

echo "==> ready: ./run_tests.sh"
