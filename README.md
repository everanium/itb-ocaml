# ITB OCaml Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, OSCCA's SM-series in China, IC3S in India, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia, CRYPTREC in Japan, KCMVP in South Korea) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Thin proxy over the libitb shared library's `ITB_Triple_*` surface
(`cmd/cshared`). Runtime FFI via ocaml-ctypes and libffi — no C stubs
to compile, no compile-time link; the `.so` / `.dylib` is resolved at
load time with `dlopen`. Every hash-name / MAC-name / cipher-name /
profile-name is an opaque string passed through to Go for validation;
the binding carries no ITB construction logic. The public surface is
the `Itb` module: `create` / `load` / `load_f` / `save` / `save_f`,
Single Message `encrypt_message` / `decrypt_message`, `rekey` /
`max_workers` / `close`, incremental stream sessions
(`encrypt_stream` / `decrypt_stream` with `write` / `end_` / `read` /
`drain_all`), the profile-record entries `inspect` / `register` /
`lookup` / `profiles`, the `version` introspection helper, and the
Go runtime knobs.

## Prerequisites (Arch Linux)

```bash
sudo pacman -S go ocaml opam dune
opam init            # once per machine
opam install ctypes ctypes-foreign alcotest
```

Generic Linux / macOS: a Go toolchain, OCaml 4.14+ with dune 3.x, and
the `ctypes` / `ctypes-foreign` opam packages (`alcotest` for the test
suite). libffi is pulled in by `ctypes-foreign`.

## Build the shared library

The convenience driver builds `libitb.so` and the dune project
(library, tests, bench, eitb) in one step:

```bash
./bindings/ocaml/build.sh
```

Equivalent manual invocation:

```bash
go build -trimpath -buildmode=c-shared \
    -o dist/linux-amd64/libitb.so ./cmd/cshared
cd bindings/ocaml && dune build
```

## Library lookup order

1. `ITB_LIBITB_PATH` environment variable (path to the shared
   library file).
2. `<repo>/dist/<os>-<arch>/libitb.<ext>` resolved by walking up from
   the executable's directory, then from the working directory
   (in-repo builds).
3. The OS default loader path (`LD_LIBRARY_PATH`, `ld.so.cache`,
   `DYLD_LIBRARY_PATH`).

A resolve failure raises `ITB_error (-1, _)` at the first FFI call.

## Usage example

```ocaml
let () =
  let sender = Itb.create "singlemsg-triple-mac-v1" () in
  let receiver = Itb.load (Itb.save sender) in

  let plain = Bytes.of_string "any text or binary data" in
  let wire = Itb.encrypt_message sender plain in
  assert (Bytes.equal (Itb.decrypt_message receiver wire) plain);

  Itb.close sender;
  Itb.close receiver
```

The `?opts` association list overrides the profile default at
`create` (chunk size, outer cipher, parallax on/off, wrapper on/off,
MAC name, palette, worker cap) — rendered into the URL-query opts
string the Go side validates. The resolved shape travels inside the
blob, so the receiver needs no options of its own:

```ocaml
let opts = [("chunkSize", "65536"); ("withWrapper", "false"); ("maxWorkers", "4")] in
let sender = Itb.create "singlemsg-triple-mac-v1" ~opts () in
let receiver = Itb.load (Itb.save sender)
```

`Itb.rekey` rotates the parallax + wrapper masters mid-session (the
eight ITB seeds and MAC key are fixed for the session lifetime by
design) and returns the fresh blob; the receiver picks up the new
masters by loading it:

```ocaml
let rotated = Itb.rekey ~perm:(Bytes.make 32 '\x11') ~wrap:(Bytes.make 32 '\x22') sender in
let receiver = Itb.load rotated
```

The same rotation is available on the receiver side as a master
override pair on `load`: `Itb.load ~perm ~wrap blob` reopens the blob
with fresh masters folded in.

## Persisting sessions

The blob returned by `Itb.save` is a self-describing session bundle:
it carries the resolved profile record, the inner key material, and
the parallax / wrapper masters. `Itb.load` reconstructs a pipeline
from it without naming a profile.

```ocaml
let blob = Itb.save sender in                     (* current blob bytes *)
let receiver = Itb.load blob in                   (* reopen from bytes *)
Itb.save_f sender "session.blob";                 (* write to a file (mode 0600) *)
let receiver2 = Itb.load_f "session.blob" in      (* reopen from a file *)
let profile = Itb.inspect blob in                 (* profile record, no pipeline *)
(* profile: {"name":"singlemsg-triple-mac-v1","mode":"singlemsg-mac",...} *)
```

`Itb.inspect` decodes the embedded profile record (a JSON object)
without constructing a pipeline. `save_f` / `load_f` perform the file
access inside libitb.

Load works for blobs generated with shipped primitives (every entry in
the shipped catalogue). Blobs generated by Go programs that use
`hashes.Register` or `macs.Register` to install custom primitives
cannot be loaded through this binding — the receiver must use the Go
library directly and register the same custom primitive under the
same name before opening. Attempting to `load` such a blob through
this binding raises `ITB_error (12, _)` (RECIPE_PRIMITIVE_UNKNOWN).

**Runtime tuning.** The worker cap is per-machine and never travels
in the blob; the receiver may pick its own after `load`:

```ocaml
Itb.max_workers receiver 4   (* clamped by libitb; <= 0 selects auto *)
```

## Profile registry

`Itb.register` installs a user-defined profile under a new name from
a profile JSON record; `Itb.lookup` reads a registered record back;
`Itb.profiles` lists every registered name. The record's field rules
are enforced by libitb; the binding treats the JSON as an opaque
string.

```ocaml
Itb.register ~name:"my-nomac-plain"
  ~profile:"{\"mode\":\"singlemsg-nomac\",\"width\":512,\"hash\":\"areion512\",\"keybits\":1024,\"wrapper\":false,\"parallax\":false}";
let record = Itb.lookup "my-nomac-plain" in      (* record with "name" filled in *)
assert (List.mem "my-nomac-plain" (Itb.profiles ()))
```

`encrypt_stream` / `decrypt_stream` open incremental sessions
exposing `write` / `end_` / `read` / `drain_all` for caller-driven
loops:

```ocaml
let pipe = Itb.create "streaming-noaead-triple-v1" () in
let enc = Itb.encrypt_stream pipe in
Itb.write enc chunk_a;
Itb.write enc chunk_b;
let wire = Itb.drain_all enc in
...
```

`create` accepts an optional `?opts` association list rendered as the
URL-query opts string the Go side validates (for example
`~opts:[("innerHash", "areion512"); ("keyBits", "1024")]`); unknown
keys are rejected by libitb with a diagnostic.

Pipelines and stream sessions register `Gc.finalise` callbacks, so
un-freed Go-side handles are reclaimed eventually; explicit `close`
zeroes a pipeline's key material deterministically, and a stream
session releases its Go-side state as soon as a `read` / `drain_all`
reports it finished. Stream sessions hold a reference to their parent
pipeline, so the parent cannot be garbage-collected while a session
is live.

Profile names, opts keys, and every primitive name are validated by
the Go side; a rejected string raises `ITB_error (status, message)`
carrying the libitb status code plus the `ITB_LastError` diagnostic
(`Itb.status_label` maps a code to a short label).

## Memory

Two process-wide knobs constrain Go runtime arena pacing, readable at
libitb load time via env vars (`ITB_GOMEMLIMIT`, `ITB_GOGC`) and
adjustable at any time programmatically:

```ocaml
Itb.set_memory_limit (512 * 1024 * 1024);
Itb.set_gc_percent 20
```

## Testing

```bash
./bindings/ocaml/run_tests.sh
```

The harness builds `libitb.so`, exports `ITB_LIBITB_PATH`, and runs
the alcotest suite. The suite covers the library version, the
shipped profile list, Single Message and stream round trips,
incremental-read loops, tampered-wire rejection, closed-handle
mapping, large-payload buffer sizing, rekey, and error mapping —
surface parity checks; the deep suite lives in Go under the shipped
tree.

## Benchmarking

```bash
./bindings/ocaml/run_bench.sh
```

Micro-benches: `encrypt_message` and stream-session encrypt
throughput at 1 MiB / 16 MiB / 64 MiB. Shape and budget are driven by
env vars (`ITB_PROFILE`, `ITB_INNER_HASH`, `ITB_KEY_BITS`,
`ITB_NONCE_BITS`, `ITB_WITH_PARALLAX`, `ITB_WITH_WRAPPER`,
`ITB_BENCH_MIN_SEC`); the script pins the same defaults as the root
Go BENCH3.md table.

## eitb utility

A small CLI under `bindings/ocaml/eitb/` mirrors the shipped Go
`tools/eitb` scope for shell smoke tests:

```bash
./bindings/ocaml/eitb/eitb version
./bindings/ocaml/eitb/eitb profiles
./bindings/ocaml/eitb/eitb encrypt singlemsg-triple-mac-v1 in.bin out.bin  # blob hex on stderr
./bindings/ocaml/eitb/eitb decrypt singlemsg-triple-mac-v1 <blob-hex> out.bin back.bin
```

`decrypt` reopens the session with `Itb.load` from the blob hex; the
profile argument only selects the Single Message or streaming cipher
pair.

The launcher builds the dune executable on demand and runs the built
binary directly, so relative file arguments resolve against the
caller's working directory.

## itb3 CLI

The shipped `itb3` binary under `cmd/itb3/` of the main repository
generates profile files (`.json` on disk) that this binding reopens
via `Itb.load_f`; the same utility also encrypts and decrypts files
directly. See `cmd/itb3/README.md` for full usage.

## Limitations

- The binding wraps the Triple Pipeline surface only. The Low-Level
  seed / MAC / blob / wrapper / parallax APIs are not exposed — use
  the shipped Go core for those.
- Streaming-decrypt caveat: chunked Streaming AEAD verifies per
  chunk, so plaintext of verified chunks is released before a later
  chunk can fail authentication.
- `ITB_LastError` is process-global last-write-wins; the textual
  diagnostic attached to an `ITB_error` may belong to a different
  call under concurrent FFI use. The status code is always
  attributable.
- `rekey` must not run concurrently with cipher calls or open stream
  sessions on the same pipeline.
- Byte buffers cross the FFI boundary zero-copy (`ocaml_bytes`); the
  OCaml runtime lock is held for the duration of each libitb call, so
  other OCaml threads do not run while Go-side cipher work is in
  flight. Single-domain callers are unaffected; Go's internal worker
  parallelism is independent of the OCaml lock.
- A stream session whose `read` / `drain_all` reported `finished`
  releases its Go-side state immediately; further calls on that
  session raise `ITB_error (-1, _)`.
