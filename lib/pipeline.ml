(* Handle-lifetime wrapper around the Triple Pipeline surface.

   A [t] value owns one Go-side Pipeline handle. [Gc.finalise]
   releases the handle when the value is collected (libitb closes and
   zeroes key material first); [close] zeroes deterministically
   without waiting for the GC. *)

open Ctypes
open Ffi_bridge

type t = { mutable handle : Unsigned.size_t (* zero after free *) }

(* Floor capacity for blob / JSON output buffers (Init / Rekey / Save /
   Inspect / Lookup / Profiles). *)
let blob_cap = 64 * 1024

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

let attach handle =
  let p = { handle } in
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
   undersized attempt is closed by libitb before returning). The Init
   blob is not retained binding-side; [save] reads the current bytes
   from libitb. *)
let init profile opts =
  let s = syms () in
  let handle = new_handle_out () in
  ignore
    (retry_once blob_cap (fun buf cap need ->
         s.triple_init profile opts (bs buf) (sz cap) need handle));
  attach !@handle

(* The masters pair crosses as (perm, wrap, count): both absent
   yields 0, otherwise 2 -- libitb validates the pair. *)
let masters_count perm wrap =
  if Bytes.length perm = 0 && Bytes.length wrap = 0 then Unsigned.Size_t.zero
  else sz 2

(* Reconstructs a Pipeline from a blob produced by [save] or [rekey].
   The profile shape travels inside the blob -- no profile name, no
   opts. *)
let load blob perm wrap =
  let s = syms () in
  let handle = new_handle_out () in
  check
    (s.triple_load (bs blob) (byte_len blob) (bs perm) (byte_len perm) (bs wrap)
       (byte_len wrap) (masters_count perm wrap) handle);
  attach !@handle

(* [load] for a blob stored at [path]; the file is read inside
   libitb. *)
let load_f path perm wrap =
  let s = syms () in
  let handle = new_handle_out () in
  check
    (s.triple_load_f path (bs perm) (byte_len perm) (bs wrap) (byte_len wrap)
       (masters_count perm wrap) handle);
  attach !@handle

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

(* The current session-bundle blob (the Init blob, or the bytes of the
   latest [rekey]). *)
let save p =
  require_live p;
  let s = syms () in
  retry_once blob_cap (fun buf cap need -> s.triple_save p.handle (bs buf) (sz cap) need)

(* Writes the current blob to [path] inside libitb (mode 0600). *)
let save_f p path =
  require_live p;
  check ((syms ()).triple_save_f p.handle path)

(* Sets the worker cap for every subsequent cipher call; [n] is
   clamped by libitb. *)
let max_workers p n =
  require_live p;
  check ((syms ()).triple_max_workers p.handle n)

(* Rotates the parallax + wrapper masters and returns the fresh blob
   (also available through [save]). Must not run concurrently with
   cipher calls or open stream sessions on the same Pipeline. *)
let rekey p perm wrap =
  require_live p;
  let s = syms () in
  retry_once blob_cap (fun buf cap need ->
      s.triple_rekey p.handle (bs perm) (byte_len perm) (bs wrap) (byte_len wrap)
        (bs buf) (sz cap) need)

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
(* Profile records                                                  *)
(* ---------------------------------------------------------------- *)

(* A profile record is the JSON object libitb accepts in [register],
   returns from [lookup] / [inspect], and embeds in every blob. The
   binding treats it as an opaque string; every field rule is
   enforced by libitb. *)

(* Decodes the profile record embedded in [blob] without constructing
   a Pipeline. *)
let inspect blob =
  let s = syms () in
  Bytes.to_string
    (retry_once blob_cap (fun buf cap need ->
         s.triple_inspect (bs blob) (byte_len blob) (bs buf) (sz cap) need))

(* Registers a user-defined Triple profile under [name] from a profile
   JSON record; a duplicate name fails with the PROFILE_EXISTS status
   (26). *)
let register name profile_json = check ((ext_syms ()).triple_register name profile_json)

(* The profile registered under [name] as its JSON record; an
   unregistered name fails with the UNKNOWN_PROFILE status (13). *)
let lookup name =
  let s = ext_syms () in
  Bytes.to_string
    (retry_once blob_cap (fun buf cap need -> s.triple_lookup name (bs buf) (sz cap) need))

(* The sorted list of every registered profile name. libitb returns a
   JSON array of strings; names match [^[a-z][a-z0-9-]+$], so the
   array splits on the quote characters alone. *)
let profiles () =
  let s = ext_syms () in
  let json =
    Bytes.to_string
      (retry_once blob_cap (fun buf cap need -> s.triple_profiles (bs buf) (sz cap) need))
  in
  let parts = String.split_on_char '"' json in
  List.filteri (fun i _ -> i mod 2 = 1) parts

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
