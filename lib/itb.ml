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

let binding_version = "0.4.1"

let create profile ?(opts = []) () = Pipeline.init profile (Pipeline.render_opts opts)

let load ?(perm = Bytes.create 0) ?(wrap = Bytes.create 0) blob =
  Pipeline.load blob perm wrap

let load_f ?(perm = Bytes.create 0) ?(wrap = Bytes.create 0) path =
  Pipeline.load_f path perm wrap

let save = Pipeline.save
let save_f = Pipeline.save_f
let max_workers = Pipeline.max_workers
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

let profiles = Pipeline.profiles

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

let inspect = Pipeline.inspect
let register ~name ~profile = Pipeline.register name profile
let lookup = Pipeline.lookup
let encrypt_stream_one_shot = Pipeline.encrypt_stream_one_shot
let decrypt_stream_one_shot = Pipeline.decrypt_stream_one_shot

(* Caller-buffer variants: allocation-free hot paths over the same
   FFI calls as the allocating entry points above. *)
let encrypt_message_into = Pipeline.encrypt_message_into
let decrypt_message_into = Pipeline.decrypt_message_into
let read_into = Stream.read_into
let write_sub = Stream.write_sub
let message_out_cap = Ffi_bridge.out_cap
