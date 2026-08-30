(* Incremental stream sessions over an open Pipeline.

   A session is a dumb byte pump: an encrypt session takes plaintext
   in through [write] and yields wire through [read] / [drain_all]; a
   decrypt session is the mirror (wire in, plaintext out). All
   chunking, MAC, envelope, and wire-format decisions stay inside
   libitb.

   The [parent] field pins the parent Pipeline via an OCaml reference
   so it cannot be garbage-collected (and its Go-side handle freed)
   while the session is still live. The Go handle registry would
   degrade a stale-pipe StreamWrite/Read to a bad-handle status, but
   the nondeterminism is a correctness trap for a caller that lets
   the parent go out of scope. *)

open Ctypes
open Ffi_bridge

(* Phantom direction tags: ['a t] is shared, [enc t] / [dec t] keep
   the two directions apart in the public signature. *)
type enc
type dec

type 'a t = {
  mutable shandle : Unsigned.size_t; (* zero after free *)
  parent : Pipeline.t; (* session-parent pin *)
  mutable ended : bool;
}

(* Feed / drain slice size used by the drain loops. *)
let pump_buf = 1 lsl 20

(* Releases the Go-side session state (cancelling it if still
   running). Safe to call more than once; runs as the GC finaliser
   and never raises. *)
let release (sess : _ t) =
  if not (Unsigned.Size_t.equal sess.shandle zero_handle) then begin
    let h = sess.shandle in
    sess.shandle <- zero_handle;
    match syms () with
    | exception ITB_error _ -> ()
    | s -> ignore (s.stream_free h)
  end

let start begin_fn (pipe : Pipeline.t) =
  Pipeline.require_live pipe;
  let handle = new_handle_out () in
  check (begin_fn pipe.Pipeline.handle handle);
  let sess = { shandle = !@handle; parent = pipe; ended = false } in
  Gc.finalise release sess;
  sess

let begin_encrypt pipe : enc t = start (syms ()).enc_stream_begin pipe
let begin_decrypt pipe : dec t = start (syms ()).dec_stream_begin pipe

let require_live (sess : _ t) =
  ignore sess.parent;
  if Unsigned.Size_t.equal sess.shandle zero_handle then
    raise (ITB_error (-1, "stream session already finished or freed"))

(* Feeds [src] into the session. Blocks until the cipher chain
   accepts the bytes; errors are sticky. *)
let write (sess : _ t) src =
  require_live sess;
  check ((syms ()).stream_write sess.shandle (bs src) (byte_len src))

(* Signals end-of-input. Idempotent; [write] after [end_] fails with
   the BAD_INPUT status. *)
let end_ (sess : _ t) =
  require_live sess;
  check ((syms ()).stream_end sess.shandle);
  sess.ended <- true

(* Drains up to [max_bytes] produced bytes; returns
   [(chunk, finished)]. Partial drains are normal; a read before
   [end_] never blocks. After [end_], an empty-spool read blocks
   until the terminal bytes arrive or the session errors. When
   [finished] comes back [true], the Go-side session state is
   released; further calls on the session raise [ITB_error (-1, _)]. *)
let read ?(max_bytes = pump_buf) (sess : _ t) =
  require_live sess;
  let s = syms () in
  let buf = Bytes.create max_bytes in
  let need = new_size_out () in
  let fin = Ctypes.allocate Ctypes.int 0 in
  check (s.stream_read sess.shandle (bs buf) (sz max_bytes) need fin);
  let n = sz_int Ctypes.(!@need) in
  let finished = Ctypes.(!@fin) <> 0 in
  if finished then release sess;
  (Bytes.sub buf 0 n, finished)

(* Calls [end_] (if not yet called), returns every remaining output
   byte, and releases the session. *)
let drain_all (sess : _ t) =
  if not sess.ended then end_ sess;
  let out = Buffer.create pump_buf in
  let rec loop () =
    let chunk, finished = read sess in
    Buffer.add_bytes out chunk;
    if finished then Buffer.to_bytes out else loop ()
  in
  loop ()

(* Caller-buffer drain primitive: fills up to [cap] bytes of [dst] in
   place and returns [(n, finished)]. [dst] is reusable across calls,
   which keeps a high-throughput drain loop free of per-slice buffer
   churn ([read] allocates a fresh chunk per call). Bytes past [n] are
   unspecified. Raises [Invalid_argument] when [cap] exceeds the real
   length of [dst] -- libitb honours [cap] as the write ceiling, so an
   oversized [cap] would license an out-of-bounds write. Same
   blocking / release semantics as [read]. *)
let read_into (sess : _ t) dst cap =
  if cap < 0 || cap > Bytes.length dst then
    invalid_arg
      (Printf.sprintf "Itb.read_into: cap %d exceeds buffer length %d" cap
         (Bytes.length dst));
  require_live sess;
  let s = syms () in
  let need = new_size_out () in
  let fin = Ctypes.allocate Ctypes.int 0 in
  check (s.stream_read sess.shandle (bs dst) (sz cap) need fin);
  let n = sz_int Ctypes.(!@need) in
  let finished = Ctypes.(!@fin) <> 0 in
  if finished then release sess;
  (n, finished)

(* Zero-copy sub-range variant of [write]: feeds [len] bytes of [src]
   starting at byte offset [pos], without slicing a fresh buffer. The
   runtime lock is held for the call, so [src] stays pinned. Raises
   [Invalid_argument] when the range escapes [src]. *)
let write_sub (sess : _ t) src pos len =
  if pos < 0 || len < 0 || pos > Bytes.length src - len then
    invalid_arg
      (Printf.sprintf "Itb.write_sub: range [%d, %d) exceeds buffer length %d"
         pos (pos + len) (Bytes.length src));
  require_live sess;
  check ((syms ()).stream_write sess.shandle Ctypes.(bs src +@ pos) (sz len))
