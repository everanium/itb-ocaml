#!/usr/bin/env bash
#
# run_bench.sh -- micro-benchmark runner for the OCaml binding. Builds
# libitb.so and the dune project via build.sh, then runs
# bench/bench.ml: encrypt_message and stream-session encrypt
# throughput at 1 MiB / 16 MiB / 64 MiB.
#
# Usage:
#   ./run_bench.sh

set -eu
set -o pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"
DIST_DIR="$REPO_ROOT/dist/linux-amd64"

./build.sh

export ITB_LIBITB_PATH="$DIST_DIR/libitb.so"

# Go-runtime pacing defaults for bench-scale allocation churn; the
# `:-` form respects any override set by the caller. The bench binary
# applies the same caps programmatically.
export ITB_GOMEMLIMIT="${ITB_GOMEMLIMIT:-512MiB}"
export ITB_GOGC="${ITB_GOGC:-20}"

# Bench-shape defaults -- match the root Go BENCH3.md pin so the
# throughput numbers are directly comparable to the shipped Go
# Encrypt3x{128,256,512}Cfg baseline. Override any of these before
# calling the script to change the shape.
export ITB_NONCE_BITS="${ITB_NONCE_BITS:-512}"
export ITB_KEY_BITS="${ITB_KEY_BITS:-1024}"
export ITB_WITH_PARALLAX="${ITB_WITH_PARALLAX:-false}"
export ITB_WITH_WRAPPER="${ITB_WITH_WRAPPER:-false}"
export ITB_INNER_HASH="${ITB_INNER_HASH:-areion512}"
export ITB_BENCH_MIN_SEC="${ITB_BENCH_MIN_SEC:-5}"

# ITB_WITH_MAC=true derives MAC/AEAD profile counterparts. When
# ITB_PROFILE is set explicitly by the caller, it wins over the
# derivation and applies to both shapes (expert override).
: "${ITB_WITH_MAC:=false}"
if [ -n "${ITB_PROFILE:-}" ]; then
    ITB_MSG_PROFILE_DEFAULT="${ITB_PROFILE}"
    ITB_STREAM_PROFILE_DEFAULT="${ITB_PROFILE}"
elif [ "${ITB_WITH_MAC}" = "true" ]; then
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-mac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-aead-triple-mac-v1"
else
    ITB_MSG_PROFILE_DEFAULT="singlemsg-triple-nomac-v1"
    ITB_STREAM_PROFILE_DEFAULT="streaming-noaead-triple-v1"
fi

if command -v opam >/dev/null 2>&1; then
    eval "$(opam env 2>/dev/null)" || true
fi

# bench/bench.exe reads ITB_MSG_PROFILE for the Message shape and
# ITB_STREAM_PROFILE for the Stream shape independently, so both
# shapes run in a single process regardless of whether they share a
# profile. Any caller-supplied ITB_MSG_PROFILE / ITB_STREAM_PROFILE
# wins over the per-shape defaults derived above.
export ITB_MSG_PROFILE="${ITB_MSG_PROFILE:-$ITB_MSG_PROFILE_DEFAULT}"
export ITB_STREAM_PROFILE="${ITB_STREAM_PROFILE:-$ITB_STREAM_PROFILE_DEFAULT}"
exec dune exec --no-print-directory bench/bench.exe
