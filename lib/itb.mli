(** Thin OCaml proxy over the libitb shared library's Triple Pipeline
    surface.

    The library wraps the [ITB_Triple_*] C ABI exported by
    [cmd/cshared] (libitb.so / .dylib / .dll) through ocaml-ctypes —
    runtime FFI, no compile-time link, no C stubs to build. Every
    hash-name / MAC-name / cipher-name / profile-name is an opaque
    string passed through to Go for validation; the binding carries
    no ITB construction logic of its own.

    Example:
    {[
      let sender = Itb.create "singlemsg-triple-mac-v1" () in
      let receiver = Itb.open_ "singlemsg-triple-mac-v1" (Itb.blob sender) in
      let wire = Itb.encrypt_message sender (Bytes.of_string "hello") in
      assert (Itb.decrypt_message receiver wire = Bytes.of_string "hello")
    ]} *)

(** Raised on every failed libitb call. The [int] is the libitb
    status code ([-1] for binding-side failures such as a
    library-load error); the [string] is the [ITB_LastError]
    diagnostic captured immediately after the failing call
    (process-global last-write-wins — under concurrent FFI use the
    message may belong to a different call; the status code is always
    attributable). *)
exception ITB_error of int * string

(** Short human-readable label for a libitb status code. *)
val status_label : int -> string

(** A Triple Pipeline session plus its exported blob bytes. The
    Go-side handle is released by a GC finaliser; [close] zeroes the
    key material deterministically without waiting for the GC. *)
type pipeline

(** Phantom direction tags for stream sessions. *)
type enc

type dec

(** An incremental stream session over an open pipeline: an
    [enc stream] takes plaintext in through [write] and yields wire
    through [read] / [drain_all]; a [dec stream] is the mirror (wire
    in, plaintext out). The session holds a reference to its parent
    pipeline, so the parent cannot be garbage-collected while the
    session is live. *)
type 'a stream

type stream_encryptor = enc stream
type stream_decryptor = dec stream

(** [create profile ?blob ?opts ()] constructs a pipeline against the
    named profile: a fresh session when [blob] is absent, or a
    session reconstructed from a received blob when present. [opts]
    is an association list rendered as the URL-query opts string the
    Go side validates (e.g. [("innerHash", "areion512")];
    unknown keys are rejected by libitb). *)
val create : string -> ?blob:bytes -> ?opts:(string * string) list -> unit -> pipeline

(** [open_ profile blob] reconstructs a pipeline from a blob produced
    by [create] (via [blob]) or refreshed by [rekey], with default
    opts. Equivalent to [create profile ~blob ()]. *)
val open_ : string -> bytes -> pipeline

(** The exported session-bundle bytes for the receiver side (a
    fresh copy on every call). *)
val blob : pipeline -> bytes

(** Single Message encrypt: one call, one self-contained wire. *)
val encrypt_message : pipeline -> bytes -> bytes

(** Receive-side counterpart of [encrypt_message]. *)
val decrypt_message : pipeline -> bytes -> bytes

(** [rekey ?perm ?wrap p] rotates the parallax + wrapper masters and
    refreshes [blob p]. A master may be omitted only when the
    corresponding layer is off for the profile. Must not run
    concurrently with cipher calls or open stream sessions on the
    same pipeline. *)
val rekey : ?perm:bytes -> ?wrap:bytes -> pipeline -> unit

(** Zeroes the pipeline's key material and marks it closed.
    Idempotent; subsequent cipher calls raise [ITB_error] with the
    TRIPLE_CLOSED status (25). The Go-side handle itself is released
    by the GC finaliser. *)
val close : pipeline -> unit

(** Opens an incremental encrypt session (plaintext in, wire out). *)
val encrypt_stream : pipeline -> stream_encryptor

(** Opens an incremental decrypt session (wire in, plaintext out). *)
val decrypt_stream : pipeline -> stream_decryptor

(** Feeds bytes into the session. Blocks until the cipher chain
    accepts them; errors are sticky. *)
val write : 'a stream -> bytes -> unit

(** Signals end-of-input. Idempotent; [write] after [end_] fails with
    the BAD_INPUT status. *)
val end_ : 'a stream -> unit

(** Drains up to [max_bytes] (default 1 MiB) produced bytes; returns
    [(chunk, finished)]. Partial drains are normal; a read before
    [end_] never blocks. When [finished] comes back [true] the
    Go-side session state is released — further calls on the session
    raise [ITB_error (-1, _)]. *)
val read : ?max_bytes:int -> 'a stream -> bytes * bool

(** Calls [end_] (if not yet called), returns every remaining output
    byte, and releases the session. *)
val drain_all : 'a stream -> bytes

(** The shipped hash primitive roster in registry order. *)
val hashes : unit -> string list

(** The shipped Triple profile names. The authoritative registry
    lives in Go; this roster mirrors it for discovery from tests and
    the shell. *)
val profiles : unit -> string list

(** The libitb library version string. *)
val version : unit -> string

(** The binding's own version string. *)
val binding_version : string

(** Sets the Go runtime's soft heap limit in bytes. *)
val set_memory_limit : int -> unit

(** Sets the Go GC trigger percentage. *)
val set_gc_percent : int -> unit

(** [register_profile ~name ~body] installs a user-defined Triple
    profile so subsequent [create] / [open_] calls resolve [name].
    [body] is the URL-query-encoded register-profile opts string
    validated by the Go side ([mode], [width], [innerHash] /
    [innerHashes], [keyBits], [macName], [outerCipher],
    [parallaxPalette], [parallaxSegmentSize], [chunkSize],
    [parallaxOn], [wrapperOn]). A duplicate name raises [ITB_error]
    with the PROFILE_EXISTS status (26). *)
val register_profile : name:string -> body:string -> unit

(** Whole-stream encrypt in a single call: the complete plaintext in,
    the complete stream wire out. The wire is byte-identical to what
    an incremental stream session produces for the same input; use
    the [encrypt_stream] session surface when the input does not fit
    in memory. *)
val encrypt_stream_one_shot : pipeline -> bytes -> bytes

(** Receive-side counterpart of [encrypt_stream_one_shot]. *)
val decrypt_stream_one_shot : pipeline -> bytes -> bytes

(** [encrypt_message_into p plain dst] is the caller-buffer variant of
    [encrypt_message]: writes the wire into [dst] and returns the byte
    count. No pre-allocation and no retry-once — the caller owns
    capacity planning ([message_out_cap] gives the standard formula);
    an undersized [dst] raises [ITB_error] with the BUFFER_TOO_SMALL
    status (5). Reusing one grow-only [dst] across calls removes the
    per-call output-buffer allocation and result copy of the
    allocating entry point. Bytes past the returned count are
    unspecified. *)
val encrypt_message_into : pipeline -> bytes -> bytes -> int

(** Receive-side counterpart of [encrypt_message_into]. *)
val decrypt_message_into : pipeline -> bytes -> bytes -> int

(** [read_into sess dst cap] is the caller-buffer drain primitive:
    fills up to [cap] bytes of [dst] in place and returns
    [(n, finished)]. [dst] is reusable across calls, which keeps a
    high-throughput drain loop free of per-slice buffer churn
    ([read] allocates a fresh chunk per call). Bytes past [n] are
    unspecified. Raises [Invalid_argument] when [cap] is negative or
    exceeds the real length of [dst] — libitb honours [cap] as the
    write ceiling, so an oversized [cap] would license an
    out-of-bounds write. Same blocking / release semantics as
    [read]. *)
val read_into : 'a stream -> bytes -> int -> int * bool

(** [write_sub sess src pos len] is the zero-copy sub-range variant of
    [write]: feeds [len] bytes of [src] starting at byte offset
    [pos], without slicing a fresh buffer. Raises [Invalid_argument]
    when the range escapes [src]. *)
val write_sub : 'a stream -> bytes -> int -> int -> unit

(** [message_out_cap n] is the standard Message output-buffer
    pre-allocation formula for an [n]-byte payload
    ([max 65536 (n * 5/4 + 65536)] — small plaintexts expand by a
    large constant factor). A [dst] sized with it never trips
    BUFFER_TOO_SMALL on the shipped profiles. *)
val message_out_cap : int -> int
