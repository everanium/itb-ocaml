(* Runtime symbol loading over the libitb shared library (ctypes +
   libffi).

   The library is loaded once per process and never unloaded, so the
   resolved function values stay valid for the process lifetime.
   Search order:

   1. [ITB_LIBITB_PATH] environment variable (path to the shared
      library file).
   2. [<repo>/dist/<os>-<arch>/libitb.<ext>] resolved by walking up
      from the executable's directory, then from the working
      directory (in-repo builds).
   3. The OS default loader path ([LD_LIBRARY_PATH], [ld.so.cache],
      [DYLD_LIBRARY_PATH]).

   A resolve failure surfaces as [ITB_error (-1, _)] at the first FFI
   call rather than a link-time crash. *)

open Ctypes

(* Raised on every failed libitb call. The [int] is the libitb status
   code ([-1] for binding-side failures such as a library-load error);
   the [string] is the [ITB_LastError] diagnostic captured immediately
   after the failing call (process-global last-write-wins -- the
   message may belong to a different call under concurrent FFI use;
   the status code is always attributable). *)
exception ITB_error of int * string

let status_ok = 0
let status_buffer_too_small = 5

(* Short human-readable label for a libitb status code, mirrored from
   cmd/cshared/internal/capi/errors.go. Numeric values are stable
   across releases. *)
let status_label = function
  | 0 -> "ok"
  | 1 -> "unknown hash name"
  | 2 -> "invalid key bits"
  | 3 -> "invalid handle"
  | 4 -> "invalid input"
  | 5 -> "output buffer too small"
  | 6 -> "encrypt failed"
  | 7 -> "decrypt failed"
  | 8 -> "seed width mismatch"
  | 9 -> "unknown MAC name or invalid MAC handle"
  | 10 -> "MAC verification failed"
  | 11 -> "blob recipe malformed"
  | 12 -> "blob recipe names an unknown primitive"
  | 13 -> "unknown profile name"
  | 19 -> "blob mode mismatch"
  | 20 -> "malformed state blob"
  | 21 -> "blob version too new"
  | 22 -> "too many blob export opts"
  | 23 -> "stream truncated before terminator"
  | 24 -> "stream chunk after terminator"
  | 25 -> "Triple Pipeline is closed"
  | 26 -> "profile name already registered"
  | 99 -> "internal error"
  | -1 -> "binding-side failure"
  | _ -> "unknown status"

(* ---------------------------------------------------------------- *)
(* Library resolution                                               *)
(* ---------------------------------------------------------------- *)

let lib_basenames = [ "libitb.so"; "libitb.dylib" ]
let dist_subdirs = [ "linux-amd64"; "linux-arm64"; "darwin-amd64"; "darwin-arm64" ]

(* All dist-layout candidates under [dir]. *)
let dist_candidates dir =
  List.concat_map
    (fun sub ->
      List.map
        (fun base -> Filename.concat (Filename.concat (Filename.concat dir "dist") sub) base)
        lib_basenames)
    dist_subdirs

(* First existing dist candidate found walking up from [start],
   at most [levels] parent hops. *)
let rec walk_up start levels =
  if levels <= 0 then None
  else
    match List.find_opt Sys.file_exists (dist_candidates start) with
    | Some p -> Some p
    | None ->
        let parent = Filename.dirname start in
        if String.equal parent start then None else walk_up parent (levels - 1)

let resolve_library_path () =
  match Sys.getenv_opt "ITB_LIBITB_PATH" with
  | Some p when String.length p > 0 -> p
  | _ -> (
      let from_exe =
        try walk_up (Filename.dirname Sys.executable_name) 12 with Sys_error _ -> None
      in
      match from_exe with
      | Some p -> p
      | None -> (
          match walk_up (Sys.getcwd ()) 12 with
          | Some p -> p
          | None -> List.hd lib_basenames))

(* ---------------------------------------------------------------- *)
(* Symbol table                                                     *)
(* ---------------------------------------------------------------- *)

(* Every prototype mirrors cmd/cshared/libitb.h. uintptr_t handles
   cross as size_t (same width on every supported platform); byte
   buffers cross as [ocaml_bytes] (zero-copy -- the runtime lock is
   held for the duration of each call, so the buffers stay pinned). *)
type syms = {
  version : Bytes.t ocaml -> Unsigned.size_t -> Unsigned.size_t ptr -> int;
  last_error : Bytes.t ocaml -> Unsigned.size_t -> Unsigned.size_t ptr -> int;
  set_memory_limit : int64 -> int64;
  set_gc_percent : int -> int;
  triple_init :
    string -> string -> Bytes.t ocaml -> Unsigned.size_t -> Unsigned.size_t ptr ->
    Unsigned.size_t ptr -> int;
  triple_load :
    Bytes.t ocaml -> Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t ->
    Bytes.t ocaml -> Unsigned.size_t -> Unsigned.size_t -> Unsigned.size_t ptr -> int;
  triple_load_f :
    string -> Bytes.t ocaml -> Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t ->
    Unsigned.size_t -> Unsigned.size_t ptr -> int;
  triple_save : Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t -> Unsigned.size_t ptr -> int;
  triple_save_f : Unsigned.size_t -> string -> int;
  triple_inspect :
    Bytes.t ocaml -> Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t ->
    Unsigned.size_t ptr -> int;
  triple_max_workers : Unsigned.size_t -> int -> int;
  triple_rekey :
    Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t -> Bytes.t ocaml ->
    Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t -> Unsigned.size_t ptr -> int;
  triple_close : Unsigned.size_t -> int;
  triple_free : Unsigned.size_t -> int;
  triple_encrypt_message :
    Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t -> Bytes.t ocaml ->
    Unsigned.size_t -> Unsigned.size_t ptr -> int;
  triple_decrypt_message :
    Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t -> Bytes.t ocaml ->
    Unsigned.size_t -> Unsigned.size_t ptr -> int;
  enc_stream_begin : Unsigned.size_t -> Unsigned.size_t ptr -> int;
  dec_stream_begin : Unsigned.size_t -> Unsigned.size_t ptr -> int;
  stream_write : Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t -> int;
  stream_end : Unsigned.size_t -> int;
  stream_read :
    Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t -> Unsigned.size_t ptr ->
    int ptr -> int;
  stream_free : Unsigned.size_t -> int;
}

let load () =
  let path = resolve_library_path () in
  let lib =
    try Dl.dlopen ~filename:path ~flags:[ Dl.RTLD_NOW ]
    with e ->
      raise
        (ITB_error
           (-1, Printf.sprintf "failed to load libitb (%s): %s" path (Printexc.to_string e)))
  in
  let f name typ = Foreign.foreign ~from:lib name typ in
  let buf_out = ocaml_bytes @-> size_t @-> ptr size_t @-> returning int in
  {
    version = f "ITB_Version" buf_out;
    last_error = f "ITB_LastError" buf_out;
    set_memory_limit = f "ITB_SetMemoryLimit" (int64_t @-> returning int64_t);
    set_gc_percent = f "ITB_SetGCPercent" (int @-> returning int);
    triple_init =
      f "ITB_Triple_Init"
        (string @-> string @-> ocaml_bytes @-> size_t @-> ptr size_t @-> ptr size_t
        @-> returning int);
    triple_load =
      f "ITB_Triple_Load"
        (ocaml_bytes @-> size_t @-> ocaml_bytes @-> size_t @-> ocaml_bytes @-> size_t
        @-> size_t @-> ptr size_t @-> returning int);
    triple_load_f =
      f "ITB_Triple_LoadF"
        (string @-> ocaml_bytes @-> size_t @-> ocaml_bytes @-> size_t @-> size_t
        @-> ptr size_t @-> returning int);
    triple_save =
      f "ITB_Triple_Save" (size_t @-> ocaml_bytes @-> size_t @-> ptr size_t @-> returning int);
    triple_save_f = f "ITB_Triple_SaveF" (size_t @-> string @-> returning int);
    triple_inspect =
      f "ITB_Triple_Inspect"
        (ocaml_bytes @-> size_t @-> ocaml_bytes @-> size_t @-> ptr size_t @-> returning int);
    triple_max_workers = f "ITB_Triple_MaxWorkers" (size_t @-> int @-> returning int);
    triple_rekey =
      f "ITB_Triple_Rekey"
        (size_t @-> ocaml_bytes @-> size_t @-> ocaml_bytes @-> size_t @-> ocaml_bytes
        @-> size_t @-> ptr size_t @-> returning int);
    triple_close = f "ITB_Triple_Close" (size_t @-> returning int);
    triple_free = f "ITB_Triple_Free" (size_t @-> returning int);
    triple_encrypt_message =
      f "ITB_Triple_EncryptMessage"
        (size_t @-> ocaml_bytes @-> size_t @-> ocaml_bytes @-> size_t @-> ptr size_t
        @-> returning int);
    triple_decrypt_message =
      f "ITB_Triple_DecryptMessage"
        (size_t @-> ocaml_bytes @-> size_t @-> ocaml_bytes @-> size_t @-> ptr size_t
        @-> returning int);
    enc_stream_begin =
      f "ITB_Triple_EncryptStreamBegin" (size_t @-> ptr size_t @-> returning int);
    dec_stream_begin =
      f "ITB_Triple_DecryptStreamBegin" (size_t @-> ptr size_t @-> returning int);
    stream_write =
      f "ITB_Triple_StreamWrite" (size_t @-> ocaml_bytes @-> size_t @-> returning int);
    stream_end = f "ITB_Triple_StreamEnd" (size_t @-> returning int);
    stream_read =
      f "ITB_Triple_StreamRead"
        (size_t @-> ocaml_bytes @-> size_t @-> ptr size_t @-> ptr int @-> returning int);
    stream_free = f "ITB_Triple_StreamFree" (size_t @-> returning int);
  }

(* Lazy so a resolve failure surfaces at the first FFI call; the
   raised exception is memoised and re-raised on every later force. *)
let syms_lazy = lazy (load ())
let syms () = Lazy.force syms_lazy

(* ---------------------------------------------------------------- *)
(* Small helpers shared by the wrapper modules                      *)
(* ---------------------------------------------------------------- *)

let sz = Unsigned.Size_t.of_int
let sz_int = Unsigned.Size_t.to_int
let zero_handle = Unsigned.Size_t.zero
let new_size_out () = allocate size_t Unsigned.Size_t.zero
let new_handle_out () = allocate size_t Unsigned.Size_t.zero
let bs = ocaml_bytes_start
let byte_len b = sz (Bytes.length b)

(* Reads the [ITB_LastError] diagnostic (NUL-stripped). Returns the
   empty string when no diagnostic is recorded or the library is
   unavailable. *)
let last_error () =
  match syms () with
  | exception ITB_error _ -> ""
  | s ->
      let read cap =
        let buf = Bytes.create cap in
        let need = new_size_out () in
        let rc = s.last_error (bs buf) (sz cap) need in
        (rc, buf, sz_int !@need)
      in
      let take buf need = Bytes.sub_string buf 0 (max (need - 1) 0) in
      let rc, buf, need = read 512 in
      if rc = status_ok && need > 1 then take buf need
      else if rc = status_buffer_too_small && need > 512 then
        let rc2, buf2, need2 = read need in
        if rc2 = status_ok && need2 > 1 then take buf2 need2 else ""
      else ""

(* Maps a raw FFI return code onto [()] / [ITB_error]. *)
let check rc = if rc <> status_ok then raise (ITB_error (rc, last_error ()))

(* Single retry-once dispatch site for every variable-size output
   buffer: pre-allocate [cap] bytes, and when the call reports
   BUFFER_TOO_SMALL with a required length strictly above the current
   capacity, retry once with the exact size the FFI reported through
   the length out-param. *)
let retry_once cap (call : Bytes.t -> int -> Unsigned.size_t ptr -> int) =
  let need = new_size_out () in
  let buf = Bytes.create cap in
  let rc = call buf cap need in
  let n = sz_int !@need in
  if rc = status_buffer_too_small && n > cap then (
    let buf2 = Bytes.create n in
    let rc2 = call buf2 n need in
    check rc2;
    Bytes.sub buf2 0 (sz_int !@need))
  else (
    check rc;
    Bytes.sub buf 0 n)

(* Pre-allocation formula for Message output buffers:
   [max 65536 (payload * 5/4 + 65536)] -- small plaintexts expand by
   a large constant factor, so the retry-once path stays available as
   the safety net. *)
let out_cap payload = max 65536 ((payload + (payload / 4)) + 65536)

(* ---------------------------------------------------------------- *)
(* Extended symbol table                                            *)
(* ---------------------------------------------------------------- *)

(* Later surface additions resolved through their own record so the
   original [syms] shape stays untouched. [Dl.dlopen] on the
   already-loaded library returns the same process handle, so the
   second resolve is cheap and never maps the library twice. *)
type ext_syms = {
  triple_register : string -> string -> int;
  triple_lookup : string -> Bytes.t ocaml -> Unsigned.size_t -> Unsigned.size_t ptr -> int;
  triple_profiles : Bytes.t ocaml -> Unsigned.size_t -> Unsigned.size_t ptr -> int;
  triple_encrypt_stream :
    Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t -> Bytes.t ocaml ->
    Unsigned.size_t -> Unsigned.size_t ptr -> int;
  triple_decrypt_stream :
    Unsigned.size_t -> Bytes.t ocaml -> Unsigned.size_t -> Bytes.t ocaml ->
    Unsigned.size_t -> Unsigned.size_t ptr -> int;
}

let load_ext () =
  let path = resolve_library_path () in
  let lib =
    try Dl.dlopen ~filename:path ~flags:[ Dl.RTLD_NOW ]
    with e ->
      raise
        (ITB_error
           (-1, Printf.sprintf "failed to load libitb (%s): %s" path (Printexc.to_string e)))
  in
  let f name typ = Foreign.foreign ~from:lib name typ in
  let cipher =
    size_t @-> ocaml_bytes @-> size_t @-> ocaml_bytes @-> size_t @-> ptr size_t
    @-> returning int
  in
  {
    triple_register = f "ITB_Triple_Register" (string @-> string @-> returning int);
    triple_lookup =
      f "ITB_Triple_Lookup" (string @-> ocaml_bytes @-> size_t @-> ptr size_t @-> returning int);
    triple_profiles =
      f "ITB_Triple_Profiles" (ocaml_bytes @-> size_t @-> ptr size_t @-> returning int);
    triple_encrypt_stream = f "ITB_Triple_EncryptStream" cipher;
    triple_decrypt_stream = f "ITB_Triple_DecryptStream" cipher;
  }

(* Lazy for the same reason as [syms_lazy]: a resolve failure surfaces
   at the first extended-surface call and is re-raised on every later
   force. *)
let ext_syms_lazy = lazy (load_ext ())
let ext_syms () = Lazy.force ext_syms_lazy
