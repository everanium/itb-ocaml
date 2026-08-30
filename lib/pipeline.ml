(* Handle-lifetime wrapper around the Triple Pipeline surface.

   A [t] value owns one Go-side Pipeline handle plus the exported
   session-bundle blob. [Gc.finalise] releases the handle when the
   value is collected (libitb closes and zeroes key material first);
   [close] zeroes deterministically without waiting for the GC. *)

open Ctypes
open Ffi_bridge

type t = {
  mutable handle : Unsigned.size_t; (* zero after free *)
  mutable blob : Bytes.t;
}

(* Floor capacity for blob output buffers (Init / Rekey). *)
let blob_cap = 64 * 1024
let empty = Bytes.create 0

(* Releases the Go-side handle. Safe to call more than once; runs as
   the GC finaliser and never raises. *)
let free p =
  if not (Unsigned.Size_t.equal p.handle zero_handle) then begin
    let h = p.handle in
    p.handle <- zero_handle;
    match syms () with
    | exception ITB_error _ -> ()
    | s -> ignore (s.triple_free h)
  end

let attach handle blob =
  let p = { handle; blob } in
  Gc.finalise free p;
  p

(* ---------------------------------------------------------------- *)
(* Opts rendering                                                   *)
(* ---------------------------------------------------------------- *)

(* Renders an association list as the URL-query-encoded opts string
   consumed by the Go side. No validation happens here -- every key
   and value is percent-encoded byte-wise (the URL-safe subset plus
   [','] passes through) and forwarded verbatim; libitb rejects
   unknown keys or bad values with a diagnostic surfaced via
   [ITB_error]. *)
let render_opts pairs =
  let enc s =
    let b = Buffer.create (String.length s) in
    String.iter
      (fun c ->
        match c with
        | 'A' .. 'Z' | 'a' .. 'z' | '0' .. '9' | '-' | '.' | '_' | '~' | ',' ->
            Buffer.add_char b c
        | c -> Buffer.add_string b (Printf.sprintf "%%%02X" (Char.code c)))
      s;
    Buffer.contents b
  in
  String.concat "&" (List.map (fun (k, v) -> enc k ^ "=" ^ enc v) pairs)

(* ---------------------------------------------------------------- *)
(* Constructors                                                     *)
(* ---------------------------------------------------------------- *)

(* Constructs a fresh Pipeline against the named profile. On a
   blob-buffer retry the Init re-runs and yields a fresh session (the
   undersized attempt is closed by libitb before returning). *)
let init profile opts =
  let s = syms () in
  let handle = new_handle_out () in
  let blob =
    retry_once blob_cap (fun buf cap need ->
        s.triple_init profile opts (bs buf) (sz cap) need handle)
  in
  attach !@handle blob

(* Reconstructs a Pipeline from a blob produced by [init] (via
   [blob]) or [rekey], using the blob-embedded masters. *)
let open_ profile blob opts =
  let s = syms () in
  let handle = new_handle_out () in
  check
    (s.triple_open profile (bs blob) (byte_len blob) opts (bs empty)
       Unsigned.Size_t.zero (bs empty) Unsigned.Size_t.zero Unsigned.Size_t.zero
       handle);
  attach !@handle (Bytes.copy blob)

(* ---------------------------------------------------------------- *)
(* Cipher calls                                                     *)
(* ---------------------------------------------------------------- *)

let require_live p =
  if Unsigned.Size_t.equal p.handle zero_handle then
    raise (ITB_error (-1, "pipeline handle already freed"))

let encrypt_message p plain =
  require_live p;
  let s = syms () in
  retry_once (out_cap (Bytes.length plain)) (fun buf cap need ->
      s.triple_encrypt_message p.handle (bs plain) (byte_len plain) (bs buf) (sz cap)
        need)

let decrypt_message p wire =
  require_live p;
  let s = syms () in
  retry_once (out_cap (Bytes.length wire)) (fun buf cap need ->
      s.triple_decrypt_message p.handle (bs wire) (byte_len wire) (bs buf) (sz cap)
        need)

(* Rotates the parallax + wrapper masters and refreshes [blob]. Must
   not run concurrently with cipher calls or open stream sessions on
   the same Pipeline. *)
let rekey p perm wrap =
  require_live p;
  let s = syms () in
  let blob =
    retry_once
      (max blob_cap (Bytes.length p.blob))
      (fun buf cap need ->
        s.triple_rekey p.handle (bs perm) (byte_len perm) (bs wrap) (byte_len wrap)
          (bs buf) (sz cap) need)
  in
  p.blob <- blob

(* Zeroes the Pipeline's key material and marks it closed.
   Idempotent; subsequent cipher calls raise [ITB_error] with the
   TRIPLE_CLOSED status. *)
let close p =
  require_live p;
  check ((syms ()).triple_close p.handle)

(* ---------------------------------------------------------------- *)
(* One-shot stream ciphers                                          *)
(* ---------------------------------------------------------------- *)

(* Whole-stream encrypt in a single call: the complete plaintext in,
   the complete stream wire out. The wire is byte-identical to what an
   incremental [Stream] session produces for the same input. *)
let encrypt_stream_one_shot p plain =
  require_live p;
  let s = ext_syms () in
  retry_once (out_cap (Bytes.length plain)) (fun buf cap need ->
      s.triple_encrypt_stream p.handle (bs plain) (byte_len plain) (bs buf) (sz cap)
        need)

(* Receive-side counterpart of [encrypt_stream_one_shot]. *)
let decrypt_stream_one_shot p wire =
  require_live p;
  let s = ext_syms () in
  retry_once (out_cap (Bytes.length wire)) (fun buf cap need ->
      s.triple_decrypt_stream p.handle (bs wire) (byte_len wire) (bs buf) (sz cap)
        need)

(* ---------------------------------------------------------------- *)
(* Profile registration                                             *)
(* ---------------------------------------------------------------- *)

(* Registers a user-defined Triple profile under [name]. [body] is
   the URL-query-encoded register-profile opts string validated by
   the Go side; a duplicate name fails with the PROFILE_EXISTS
   status (26). *)
let register_profile name body =
  check ((ext_syms ()).triple_register_profile name body)

(* ---------------------------------------------------------------- *)
(* Caller-buffer cipher calls                                       *)
(* ---------------------------------------------------------------- *)

(* Caller-buffer variant of [encrypt_message]: writes the wire into
   [dst] and returns the byte count. No pre-allocation and no
   retry-once -- the caller owns capacity planning ([out_cap] gives
   the standard formula); an undersized [dst] raises [ITB_error] with
   the BUFFER_TOO_SMALL status. Reusing one grow-only [dst] across
   calls removes the per-call output-buffer allocation and result
   copy of the allocating entry point. Bytes past the returned count
   are unspecified. *)
let encrypt_message_into p plain dst =
  require_live p;
  let s = syms () in
  let need = new_size_out () in
  check
    (s.triple_encrypt_message p.handle (bs plain) (byte_len plain) (bs dst)
       (byte_len dst) need);
  sz_int !@need

(* Receive-side counterpart of [encrypt_message_into]. *)
let decrypt_message_into p wire dst =
  require_live p;
  let s = syms () in
  let need = new_size_out () in
  check
    (s.triple_decrypt_message p.handle (bs wire) (byte_len wire) (bs dst)
       (byte_len dst) need);
  sz_int !@need
