(* Public surface of the OCaml binding; see itb.mli for the
   documented signature. Implementation lives in Ffi_bridge (symbol
   loading, status mapping, retry-once buffers), Pipeline (handle
   lifetime, Message cipher calls), and Stream (incremental
   sessions). *)

open Ctypes

exception ITB_error = Ffi_bridge.ITB_error

let status_label = Ffi_bridge.status_label

type pipeline = Pipeline.t
type enc = Stream.enc
type dec = Stream.dec
type 'a stream = 'a Stream.t
type stream_encryptor = enc stream
type stream_decryptor = dec stream

let binding_version = "0.3.3"

(* Shipped Triple profile names. The authoritative registry lives in
   Go; this roster mirrors it for discovery from tests and the
   shell. *)
let shipped_profiles =
  [
    "streaming-aead-triple-mac-v1";
    "streaming-noaead-triple-v1";
    "singlemsg-triple-mac-v1";
    "singlemsg-triple-nomac-v1";
    "blob-triple-mac-v1";
    "streaming-aead-triple-mac-mixed-v1";
    "streaming-noaead-triple-mixed-v1";
    "singlemsg-triple-mac-mixed-v1";
    "singlemsg-triple-nomac-mixed-v1";
  ]

let create profile ?blob ?(opts = []) () =
  let opts_str = Pipeline.render_opts opts in
  match blob with
  | None -> Pipeline.init profile opts_str
  | Some b -> Pipeline.open_ profile b opts_str

let open_ profile blob = Pipeline.open_ profile blob ""
let blob (p : pipeline) = Bytes.copy p.Pipeline.blob
let encrypt_message = Pipeline.encrypt_message
let decrypt_message = Pipeline.decrypt_message

let rekey ?(perm = Bytes.create 0) ?(wrap = Bytes.create 0) p =
  Pipeline.rekey p perm wrap

let close = Pipeline.close
let encrypt_stream = Stream.begin_encrypt
let decrypt_stream = Stream.begin_decrypt
let write = Stream.write
let end_ = Stream.end_
let read = Stream.read
let drain_all = Stream.drain_all

let hashes () =
  let s = Ffi_bridge.syms () in
  List.init (s.hash_count ()) (fun i ->
      let cap = 128 in
      let buf = Bytes.create cap in
      let need = Ffi_bridge.new_size_out () in
      Ffi_bridge.check (s.hash_name i (Ffi_bridge.bs buf) (Ffi_bridge.sz cap) need);
      Bytes.sub_string buf 0 (max (Ffi_bridge.sz_int !@need - 1) 0))

let profiles () = shipped_profiles

let version () =
  let s = Ffi_bridge.syms () in
  let read cap =
    let buf = Bytes.create cap in
    let need = Ffi_bridge.new_size_out () in
    let rc = s.version (Ffi_bridge.bs buf) (Ffi_bridge.sz cap) need in
    (rc, buf, Ffi_bridge.sz_int !@need)
  in
  let take buf need = Bytes.sub_string buf 0 (max (need - 1) 0) in
  let rc, buf, need = read 256 in
  if rc = Ffi_bridge.status_buffer_too_small && need > 256 then (
    let rc2, buf2, need2 = read need in
    Ffi_bridge.check rc2;
    take buf2 need2)
  else (
    Ffi_bridge.check rc;
    take buf need)

let set_memory_limit bytes_limit =
  let s = Ffi_bridge.syms () in
  ignore (s.set_memory_limit (Int64.of_int bytes_limit))

let set_gc_percent pct =
  let s = Ffi_bridge.syms () in
  ignore (s.set_gc_percent pct)

let register_profile ~name ~body = Pipeline.register_profile name body
let encrypt_stream_one_shot = Pipeline.encrypt_stream_one_shot
let decrypt_stream_one_shot = Pipeline.decrypt_stream_one_shot

(* Caller-buffer variants: allocation-free hot paths over the same
   FFI calls as the allocating entry points above. *)
let encrypt_message_into = Pipeline.encrypt_message_into
let decrypt_message_into = Pipeline.decrypt_message_into
let read_into = Stream.read_into
let write_sub = Stream.write_sub
let message_out_cap = Ffi_bridge.out_cap
