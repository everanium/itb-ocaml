(* Long-run stress harness. The loop utility holds one Pipeline handle
   per exercised cipher surface for minutes, hammers it with encrypt ->
   decrypt -> compare round-trips, rotates the outer masters and
   reopens the handle from its session blob on a schedule, and reports
   whether the process survived with every byte intact. It is the OCaml
   binding's counterpart of the Go harness under tools/loop: the same
   flags, the same round structure, the same summary in both
   renderings.

   The default shape is full production: the Streaming AEAD profile
   with parallax on, wrapper on, hmac-blake3 MAC, Areion-SoEM-512 inner
   hash, 1024-bit keys, and the compile-in 512-bit nonce width, driven
   through a stream session for five minutes on 16 MiB plaintexts.
   Every worker owns a distinct CSPRNG-generated plaintext held for the
   whole run, so any cross-call state leakage inside the Pipeline
   surfaces as a data mismatch between workers rather than cancelling
   out.

   A failure is one of two things. A cipher, rekey or load call that
   returns a non-OK status is a worker error: the run stops, the
   summary lists it, the verdict is FAIL and the exit code 1. A
   round-trip that returns without error but with different bytes is a
   data mismatch: the process terminates on the spot with exit code 3,
   printing the worker, the iteration and the first differing offset,
   and no summary -- the state that produced the wrong bytes is the
   evidence. A crash inside the shared library or the host runtime has
   no exit code of its own here; surfacing it is what the utility is
   for.

   Usage:

     ./run_loop.sh --duration 5m --goroutines 1 --shape stream \
         --hash areion512 --mac hmac-blake3 --payload-size 16MB \
         --memlimit auto --parallax on --wrapper on

   Ctrl-C triggers a graceful shutdown: the in-flight iteration
   completes, then the partial summary prints. *)

open Decls

(* Profiles the shape-based pair is built against when --profile is
   empty. *)
let default_stream_profile = "streaming-aead-triple-mac-v1"
let default_message_profile = "singlemsg-triple-mac-v1"

(* The primitive supplied for the parallax palette and the outer cipher
   when a profile leaves them unnamed. AES-CMAC is PRF-grade, so it is
   sound outside the Interlocked Barrier, and it is the closest
   relative of the AES-based inner primitive whose profiles need this
   fill. *)
let keystream_fill_cipher = "aescmac"

(* ---------------------------------------------------------------- *)
(* Flags                                                            *)
(* ---------------------------------------------------------------- *)

type kind = Kind_int | Kind_int64 | Kind_uint64 | Kind_string | Kind_bool
type raw = Rint of int | Ruint of int64 | Rstring of string | Rbool of bool

(* One command-line flag: its name, the type label the usage prints,
   its kind, its default, and its help text. Values are validated after
   the whole line is parsed. The table is in alphabetical order, which
   is the order the usage prints. *)
let flags =
  [
    ("barrier-fill", "int", Kind_int, Rint 0,
     "DRBG barrier fill margin: 1 | 2 | 4 | 8 | 16 | 32; 0 = profile default (1)");
    ("blob-cycle-every", "int", Kind_int64, Rint 0,
     "reopen each pipeline from its session blob every N iterations per worker; 0 = never");
    ("blob-mode", "int", Kind_int, Rint 1,
     "container floor sizing mode: 1 (per-region, default) | 2 (per-container)");
    ("chunk-size", "string", Kind_string, Rstring "0",
     "streaming chunk-size budget (e.g. 4MB); 0 = profile default; inert for pure message shape");
    ("drbg", "string", Kind_string, Rstring "",
     "DRBG fill primitive name (see itb3 drbgs); empty = profile default (auto tier)");
    ("duration", "duration", Kind_string, Rstring "5m",
     "run duration (Go format: 30s / 5m / 1h); ignored when --iterations > 0");
    ("gogc", "int", Kind_int, Rint 0,
     "GC trigger percentage; 0 = leave the runtime default");
    ("gomaxprocs", "int", Kind_int, Rint 0,
     "Go runtime GOMAXPROCS override; 0 = inherit from the environment");
    ("goroutines", "int", Kind_int, Rint 3,
     "concurrent workers (1..10); on runtimes without parallelism values above 1 are clamped to 1");
    ("hash", "string", Kind_string, Rstring "areion512", "inner ITB hash primitive name");
    ("iterations", "int", Kind_int64, Rint 0,
     "fixed per-worker iteration count; 0 = duration-based");
    ("json-output", "", Kind_bool, Rbool false,
     "print the final summary as one compact JSON object instead of log lines");
    ("key-bits", "int", Kind_int, Rint 0,
     "per-seed key width in bits: 512 | 1024 | 2048; 0 = profile default (1024)");
    ("mac", "string", Kind_string, Rstring "hmac-blake3", "MAC primitive name");
    ("memlimit", "string", Kind_string, Rstring "auto",
     "Go heap soft limit: auto (1GiB when goroutines <= 3, else 256MiB, applied only when the runtime has no limit) or a size (e.g. 512MB)");
    ("memprofile", "string", Kind_string, Rstring "",
     "write a Go runtime heap profile (pprof) to this path at the end of the run; empty = none");
    ("nonce-bits", "int", Kind_int, Rint 0,
     "on-wire nonce width in bits: 128 | 256 | 512; 0 = profile default (512)");
    ("parallax", "string", Kind_string, Rstring "on", "parallax layer: on | off");
    ("payload-mode", "string", Kind_string, Rstring "fixed",
     "plaintext content: fixed | rotating | pattern-zero | pattern-ff | pattern-ascii");
    ("payload-size", "string", Kind_string, Rstring "16MB",
     "per-iteration plaintext size (e.g. 1MB / 16MB / 64MB)");
    ("profile", "string", Kind_string, Rstring "",
     "exercise this single registered triple profile (overrides --shape with the profile's surface); empty = shape-based profile pair");
    ("rekey-every", "int", Kind_int64, Rint 0,
     "rotate the parallax + wrapper masters via Rekey every N iterations per worker; 0 = never");
    ("seed", "uint", Kind_uint64, Ruint 0L,
     "deterministic plaintext RNG seed for bug reproduction, NOT for security testing (pipeline keys stay CSPRNG-drawn); 0 = crypto/rand plaintexts");
    ("shape", "string", Kind_string, Rstring "stream",
     "cipher surface to exercise: stream | message | stream_one_shot | both");
    ("wrapper", "string", Kind_string, Rstring "on", "wrapper layer: on | off");
  ]

let int32_max = 2147483647

let usage () =
  let out = Buffer.create 4096 in
  Buffer.add_string out "Usage of loop:\n";
  List.iter
    (fun (name, label, kind, default, help) ->
      Buffer.add_string out
        (Printf.sprintf "  -%s%s%s\n" name (if label = "" then "" else " ") label);
      Buffer.add_string out (Printf.sprintf "    \t%s" help);
      (* The default-value suffix follows the shape a Go flag set
         prints: an integer default only when it is non-zero, a string
         default only when it is non-empty. *)
      (match (kind, default) with
      | Kind_int, Rint v when v <> 0 ->
          Buffer.add_string out (Printf.sprintf " (default %d)" v)
      | Kind_string, Rstring v when v <> "" ->
          Buffer.add_string out (Printf.sprintf " (default \"%s\")" v)
      | _ -> ());
      Buffer.add_char out '\n')
    flags;
  write_all Unix.stderr (Buffer.contents out)

let all_digits s = s <> "" && String.for_all (fun c -> c >= '0' && c <= '9') s

(* Parses one value into its flag slot; None on a malformed value. *)
let assign_flag kind value =
  match kind with
  | Kind_int | Kind_int64 -> (
      let body =
        if String.length value > 0 && (value.[0] = '-' || value.[0] = '+') then
          String.sub value 1 (String.length value - 1)
        else value
      in
      if not (all_digits body) then None
      else
        match Int64.of_string_opt value with
        | None -> None
        | Some n ->
            if
              kind = Kind_int
              && (n > Int64.of_int int32_max || n < Int64.of_int (-int32_max))
            then None
            else if Int64.abs n > Int64.of_int max_int then None
            else Some (Rint (Int64.to_int n)))
  | Kind_uint64 ->
      if String.length value > 0 && value.[0] = '-' then None
      else begin
        let body =
          if String.length value > 0 && value.[0] = '+' then
            String.sub value 1 (String.length value - 1)
          else value
        in
        if not (all_digits body) then None
        else
          (* The grammar is a 64-bit unsigned decimal, which
             [Int64.of_string] reads as a bit pattern when prefixed. *)
          match Int64.of_string_opt ("0u" ^ body) with
          | None -> None
          | Some n -> Some (Ruint n)
      end
  | Kind_string -> Some (Rstring value)
  | Kind_bool ->
      if value = "true" then Some (Rbool true)
      else if value = "false" then Some (Rbool false)
      else None

(* Parses argv into the raw flag values. Accepts -name value, --name
   value, -name=value and --name=value; a boolean flag takes no value
   unless given as -name=true / -name=false. Returns 0, 1 for -h /
   --help (usage printed), or -1 after printing the error. *)
let parse_argv argv table =
  let kinds = List.map (fun (name, _, kind, _, _) -> (name, kind)) flags in
  let n = Array.length argv in
  let i = ref 0 in
  let rc = ref 0 in
  while !rc = 0 && !i < n do
    let arg = argv.(!i) in
    if String.length arg < 2 || arg.[0] <> '-' then begin
      err_line (Printf.sprintf "unexpected positional arguments: [%s]" arg);
      rc := -1
    end
    else begin
      let body =
        if String.length arg > 1 && arg.[1] = '-' then String.sub arg 2 (String.length arg - 2)
        else String.sub arg 1 (String.length arg - 1)
      in
      if body = "h" || body = "help" then begin
        usage ();
        rc := 1
      end
      else begin
        let name, given =
          match String.index_opt body '=' with
          | Some eq ->
              ( String.sub body 0 eq,
                Some (String.sub body (eq + 1) (String.length body - eq - 1)) )
          | None -> (body, None)
        in
        match List.assoc_opt name kinds with
        | None ->
            err_line (Printf.sprintf "flag provided but not defined: -%s" name);
            usage ();
            rc := -1
        | Some kind -> (
            let value =
              match given with
              | Some v -> Some v
              | None ->
                  if kind = Kind_bool then Some "true"
                  else if !i + 1 < n then begin
                    incr i;
                    Some argv.(!i)
                  end
                  else None
            in
            match value with
            | None ->
                err_line (Printf.sprintf "flag needs an argument: -%s" name);
                rc := -1
            | Some v -> (
                match assign_flag kind v with
                | None ->
                    err_line (Printf.sprintf "invalid value \"%s\" for flag -%s" v name);
                    rc := -1
                | Some parsed ->
                    Hashtbl.replace table name parsed;
                    incr i))
      end
    end
  done;
  !rc

let raw_int table name = match Hashtbl.find table name with Rint v -> v | _ -> 0
let raw_uint table name = match Hashtbl.find table name with Ruint v -> v | _ -> 0L
let raw_string table name = match Hashtbl.find table name with Rstring v -> v | _ -> ""
let raw_bool table name = match Hashtbl.find table name with Rbool v -> v | _ -> false

(* Maps "on" / "off" to a bool; None otherwise. *)
let parse_on_off = function "on" -> Some true | "off" -> Some false | _ -> None

(* Whether name is in the shipped hash registry the binding
   enumerates. *)
let hash_registered name =
  match Itb3.hash_names () with
  | names -> List.mem name names
  | exception Itb3.ITB_error _ -> false

(* OCaml-specific. The binding returns a profile record as the JSON
   text the library wrote, so the four readers below probe that text
   directly. Record keys are fixed and record strings are restricted to
   [a-z0-9-], so a quoted run is one complete value and a key match is
   unambiguous. *)
let find_sub hay needle =
  let n = String.length needle and h = String.length hay in
  let rec go i =
    if i + n > h then None else if String.sub hay i n = needle then Some i else go (i + 1)
  in
  go 0

let record_has json key = find_sub json ("\"" ^ key ^ "\":") <> None

let record_int json key =
  match find_sub json ("\"" ^ key ^ "\":") with
  | None -> 0
  | Some at ->
      let start = at + String.length key + 3 in
      let i = ref start in
      if !i < String.length json && json.[!i] = '-' then incr i;
      while !i < String.length json && json.[!i] >= '0' && json.[!i] <= '9' do
        incr i
      done;
      if !i = start then 0
      else (
        match int_of_string_opt (String.sub json start (!i - start)) with
        | None -> 0
        | Some v -> v)

let record_str json key =
  match find_sub json ("\"" ^ key ^ "\":\"") with
  | None -> "-"
  | Some at -> (
      let start = at + String.length key + 4 in
      match String.index_from_opt json start '"' with
      | None -> "-"
      | Some close -> if close = start then "-" else String.sub json start (close - start))

let record_bool json key = record_has json key && find_sub json ("\"" ^ key ^ "\":true") <> None

(* Folds a keystream primitive into opts for any layer the named
   profile leaves unfilled but the operator asked for.

   A profile built around a primitive that is safe only inside the
   Interlocked Barrier ships with no parallax palette and no outer
   cipher: both layers run outside the barrier, where that primitive
   would stand bare, so the recipe leaves them unnamed rather than
   naming a primitive that must not key them. Engaging either layer
   therefore needs a keystream-capable primitive supplied from outside
   the recipe; without it construction fails on a palette below its
   minimum or an unnamed outer cipher, and the primitive that most
   deserves stressing becomes the one that cannot be stressed with
   those layers engaged.

   Overrides fold into the resolved record the blob carries, so the
   receiver rebuilds the same shape from the blob alone.

   Returns the extra opts pairs and whether a layer was filled, or None
   on a lookup failure (message already printed). *)
let fill_keystream_layers name want_parallax want_wrapper =
  match Itb3.lookup name with
  | exception Itb3.ITB_error _ ->
      err_line (Printf.sprintf "--profile \"%s\" is not a registered triple profile" name);
      None
  | json ->
      let extra = ref [] in
      if want_parallax && not (record_has json "palette") then begin
        extra :=
          ( "parallaxPalette",
            String.concat ","
              [ keystream_fill_cipher; keystream_fill_cipher; keystream_fill_cipher ] )
          :: !extra;
        (* A recipe that never carried a palette never carried a segment
           size either, and the schedule rejects zero. *)
        if not (record_has json "segment") then
          extra := ("parallaxSegmentSize", "4093") :: !extra
      end;
      if want_wrapper && not (record_has json "outer") then
        extra := ("outerCipher", keystream_fill_cipher) :: !extra;
      Some (List.rev !extra)

(* Resolves a registered profile to the shape family its record's mode
   exposes by reading the record through the binding's lookup: a mode
   beginning with "streaming" exposes the stream surfaces, one
   beginning with "singlemsg" the message surface, "blob-only" none.
   Prints the validation message and returns None on rejection. *)
let profile_surface name =
  match Itb3.lookup name with
  | exception Itb3.ITB_error _ ->
      err_line (Printf.sprintf "--profile \"%s\" is not a registered triple profile" name);
      None
  | json ->
      let mode = record_str json "mode" in
      let starts prefix =
        String.length mode >= String.length prefix
        && String.sub mode 0 (String.length prefix) = prefix
      in
      if starts "streaming" then Some Stream
      else if starts "singlemsg" then Some Message
      else begin
        err_line
          (Printf.sprintf "--profile \"%s\" carries no cipher surface (blob-only mode)" name);
        None
      end

(* Applies a --profile's surface to the requested shape: a
   message-surface profile forces message; a stream-surface profile
   keeps stream or stream_one_shot as requested and turns message or
   both into stream. *)
let narrow_shape requested surface =
  if surface = Message then Message
  else if requested = Stream_one_shot then Stream_one_shot
  else Stream

exception Reject

(* Builds the resolved config from argv. Returns (0, cfg), (1, cfg) for
   help, or (-1, cfg) after printing "loop: <message>" for the first
   failing rule. *)
let parse_flags argv =
  let cfg = default_config () in
  let table = Hashtbl.create 32 in
  List.iter (fun (name, _, _, default, _) -> Hashtbl.replace table name default) flags;
  let rc = parse_argv argv table in
  if rc <> 0 then (rc, cfg)
  else begin
    let reject text =
      err_line text;
      raise Reject
    in
    try
      (match Size.parse_duration (raw_string table "duration") with
      | Some ns when ns > 0 -> cfg.duration_ns <- ns
      | _ ->
          reject
            (Printf.sprintf "--duration must be positive, got %s" (raw_string table "duration")));
      cfg.iterations <- raw_int table "iterations";
      if cfg.iterations < 0 then
        reject (Printf.sprintf "--iterations must be >= 0, got %d" cfg.iterations);
      let goroutines = raw_int table "goroutines" in
      if goroutines < 1 || goroutines > max_workers then
        reject
          (Printf.sprintf "--goroutines must be in 1..%d, got %d" max_workers goroutines);
      (* Concurrency mode. This binding runs single. Its FFI layer hands
         the library pointers into the managed heap, so the runtime lock
         is held for the whole duration of every call; the only
         threading primitive available under the compiler range the
         package declares multiplexes inside that one lock, which
         leaves no two cipher calls ever in flight at once. --goroutines
         is therefore recorded as requested and the effective count
         clamped to 1, and the summary reports both so a fleet report
         cannot read a clamped run as a concurrent one. *)
      cfg.workers_requested <- goroutines;
      cfg.workers <- 1;
      (match Worker.parse_shape (raw_string table "shape") with
      | Some shape -> cfg.shape <- shape
      | None ->
          reject
            (Printf.sprintf
               "--shape must be stream | message | stream_one_shot | both, got \"%s\""
               (raw_string table "shape")));
      if not (hash_registered (raw_string table "hash")) then
        reject
          (Printf.sprintf "--hash \"%s\" is not a registered hash primitive"
             (raw_string table "hash"));
      cfg.hash <- raw_string table "hash";
      (* Validated by Init: the C ABI enumerates no MAC names. *)
      cfg.mac <- raw_string table "mac";
      (match Size.parse_size (raw_string table "payload-size") with
      | Some n -> cfg.payload <- n
      | None ->
          reject
            (Printf.sprintf "--payload-size: invalid size \"%s\""
               (raw_string table "payload-size")));
      if cfg.payload < 1 then reject "--payload-size must be at least 1 byte";
      (if raw_string table "memlimit" = "auto" then begin
         cfg.memlimit_auto <- true;
         cfg.memlimit <- (if cfg.workers <= 3 then 1073741824L else 268435456L)
       end
       else
         match Size.parse_size (raw_string table "memlimit") with
         | Some n -> cfg.memlimit <- Int64.of_int n
         | None ->
             reject
               (Printf.sprintf "--memlimit: invalid size \"%s\"" (raw_string table "memlimit")));
      cfg.gogc <- raw_int table "gogc";
      if cfg.gogc < 0 then reject (Printf.sprintf "--gogc must be >= 0, got %d" cfg.gogc);
      (match parse_on_off (raw_string table "parallax") with
      | Some v -> cfg.parallax <- v
      | None ->
          reject
            (Printf.sprintf "--parallax must be on | off, got \"%s\""
               (raw_string table "parallax")));
      (match parse_on_off (raw_string table "wrapper") with
      | Some v -> cfg.wrapper <- v
      | None ->
          reject
            (Printf.sprintf "--wrapper must be on | off, got \"%s\""
               (raw_string table "wrapper")));
      cfg.profile <- raw_string table "profile";
      if cfg.profile <> "" then begin
        match profile_surface cfg.profile with
        | None -> raise Reject
        | Some surface -> cfg.shape <- narrow_shape cfg.shape surface
      end;
      cfg.key_bits <- raw_int table "key-bits";
      if not (List.mem cfg.key_bits [ 0; 512; 1024; 2048 ]) then
        reject
          (Printf.sprintf
             "--key-bits must be 512 | 1024 | 2048 (or 0 = profile default), got %d"
             cfg.key_bits);
      cfg.nonce_bits <- raw_int table "nonce-bits";
      if not (List.mem cfg.nonce_bits [ 0; 128; 256; 512 ]) then
        reject
          (Printf.sprintf
             "--nonce-bits must be 128 | 256 | 512 (or 0 = profile default), got %d"
             cfg.nonce_bits);
      cfg.blob_mode <- raw_int table "blob-mode";
      if not (List.mem cfg.blob_mode [ 1; 2 ]) then
        reject
          (Printf.sprintf
             "--blob-mode must be 1 (per-region) | 2 (per-container), got %d"
             cfg.blob_mode);
      cfg.barrier_fill <- raw_int table "barrier-fill";
      if not (List.mem cfg.barrier_fill [ 0; 1; 2; 4; 8; 16; 32 ]) then
        reject
          (Printf.sprintf
             "--barrier-fill must be 1 | 2 | 4 | 8 | 16 | 32 (or 0 = profile default), got %d"
             cfg.barrier_fill);
      (* Validated by Init: the C ABI enumerates no DRBG names. *)
      cfg.drbg <- raw_string table "drbg";
      (match Size.parse_size (raw_string table "chunk-size") with
      | Some n -> cfg.chunk_size <- n
      | None ->
          reject
            (Printf.sprintf "--chunk-size: invalid size \"%s\""
               (raw_string table "chunk-size")));
      cfg.gomaxprocs <- raw_int table "gomaxprocs";
      if cfg.gomaxprocs < 0 then
        reject
          (Printf.sprintf "--gomaxprocs must be > 0 when specified, got %d" cfg.gomaxprocs);
      cfg.rekey_every <- raw_int table "rekey-every";
      if cfg.rekey_every < 0 then
        reject (Printf.sprintf "--rekey-every must be >= 0, got %d" cfg.rekey_every);
      cfg.blob_cycle_every <- raw_int table "blob-cycle-every";
      if cfg.blob_cycle_every < 0 then
        reject
          (Printf.sprintf "--blob-cycle-every must be >= 0, got %d" cfg.blob_cycle_every);
      (match Payload.parse_payload_mode (raw_string table "payload-mode") with
      | Some mode -> cfg.payload_mode <- mode
      | None ->
          reject
            (Printf.sprintf
               "--payload-mode must be %s, got \"%s\""
               (String.concat " | " (List.map snd Payload.payload_names))
               (raw_string table "payload-mode")));
      cfg.seed <- raw_uint table "seed";
      cfg.json_output <- raw_bool table "json-output";
      cfg.memprofile <- raw_string table "memprofile";
      (0, cfg)
    with Reject -> (-1, cfg)
  end

(* ---------------------------------------------------------------- *)
(* Signals                                                          *)
(* ---------------------------------------------------------------- *)

let signal_seen = ref false
let stop_requested () = !signal_seen

(* Graceful stop. SIGINT / SIGTERM set a flag the worker loop checks
   before it starts an iteration, so a signal interrupts nothing
   mid-call -- the in-flight encrypt / decrypt / compare completes, the
   worker returns, and the partial summary prints with the verdict the
   completed iterations earned. The runtime runs the handler at its
   next polling point, which is after the library call in progress has
   returned, so the ordering the contract asks for is the one the
   runtime already gives. *)
let install_signals () =
  let handler = Sys.Signal_handle (fun _ -> signal_seen := true) in
  Sys.set_signal Sys.sigint handler;
  Sys.set_signal Sys.sigterm handler

(* A consumer that stops reading ends the run. The default disposition
   for SIGPIPE is restored so the process dies from the signal with
   status 141 and prints nothing -- the reference behaviour, and what
   anyone piping into head or less expects.

   It runs before anything else, because the first line is already a
   write that can fail and because the shared library captures the
   disposition in force when it loads: whatever stands here at that
   moment is what the library forwards a SIGPIPE to afterwards. *)
let restore_sigpipe () = Sys.set_signal Sys.sigpipe Sys.Signal_default

(* ---------------------------------------------------------------- *)
(* Pipelines                                                        *)
(* ---------------------------------------------------------------- *)

(* Prints the construction line with the recipe read back from the blob
   the Pipeline handed out, not echoed from the flags: every
   construction override is proven to have reached the library by the
   value the receiver would see. Record values that are empty (a No MAC
   profile's MAC, a mixed profile's single hash) print as "-". *)
let log_pipeline_initialised profile blob =
  match Itb3.inspect blob with
  | exception Itb3.ITB_error (_, message) ->
      log_line
        (Printf.sprintf "pipeline initialised: profile=%s blob=%d bytes (inspect: %s)"
           profile (Bytes.length blob) message)
  | json ->
      log_line
        (Printf.sprintf
           "pipeline initialised: profile=%s blob=%d bytes hash=%s key-bits=%d \
            nonce-bits=%d barrier-fill=%d chunk-size=%d mac=%s parallax=%s wrapper=%s%s%s"
           profile (Bytes.length blob) (record_str json "hash") (record_int json "keybits")
           (record_int json "nonce_bits") (record_int json "barrier_fill")
           (record_int json "chunk") (record_str json "mac")
           (on_off (record_bool json "parallax"))
           (on_off (record_bool json "wrapper"))
           (if record_int json "container_mode" = 2 then " container-mode=2" else "")
           (match record_str json "drbg" with "-" -> "" | d -> " drbg=" ^ d))

(* Sets the inner blob's "mode" field of a wrap-layer session blob to
   target_mode (1 = per-region, 2 = per-container) in place. The wrap
   layer's profile record carries its own "mode" (a string), so the
   search starts at the inner blob ("ib"); both shipped modes are one
   digit wide, so the blob length does not change. Returns false when
   the inner blob or its mode field is not found.

   OCaml-specific. The binding carries no JSON library and reads
   profile records by targeted string handling, so the edit replaces
   the single digit rather than re-serialising the blob. *)
let edit_inner_blob_mode blob target_mode =
  let text = Bytes.to_string blob in
  let ib_key = "\"ib\":{" and mode_key = "\"mode\":" in
  match find_sub text ib_key with
  | None -> false
  | Some ib -> (
      let off = ib + String.length ib_key in
      let tail = String.sub text off (String.length text - off) in
      match find_sub tail mode_key with
      | None -> false
      | Some m ->
          let at = off + m + String.length mode_key in
          let digit c = c >= '0' && c <= '9' in
          if at + 1 >= String.length text
             || text.[at] < '1' || text.[at] > '2'
             || digit text.[at + 1]
          then false
          else (
            Bytes.set blob at (Char.chr (Char.code '0' + target_mode));
            true))

(* Constructs one Pipeline against profile with every flag-carried
   override in the opts string (zero values included -- the shared
   library treats zero as "profile default"), then obtains the Init
   blob once through save: the binding's init entry does not hand the
   blob back, and the bytes are the ones Init produced. Later blob
   reopens use the retained blob; save is never called again. *)
let build_pipeline cfg profile =
  let base =
    [
      ("innerHash", cfg.hash);
      ("macName", cfg.mac);
      ("withParallax", string_of_bool cfg.parallax);
      ("withWrapper", string_of_bool cfg.wrapper);
      ("keyBits", string_of_int cfg.key_bits);
      ("nonceBits", string_of_int cfg.nonce_bits);
      ("barrierFill", string_of_int cfg.barrier_fill);
      ("drbg", cfg.drbg);
      ("chunkSize", string_of_int cfg.chunk_size);
    ]
  in
  let extra =
    if cfg.profile = "" then Some []
    else
      match fill_keystream_layers cfg.profile cfg.parallax cfg.wrapper with
      | None -> None
      | Some [] -> Some []
      | Some pairs ->
          err_line
            (Printf.sprintf
               "%s leaves the requested keystream layers unnamed; %s supplied for them"
               cfg.profile keystream_fill_cipher);
          Some pairs
  in
  match extra with
  | None -> None
  | Some pairs -> (
      match Itb3.create profile ~opts:(base @ pairs) () with
      | exception exn ->
          err_line (Printf.sprintf "Init(%s): %s" profile (status_detail exn));
          None
      | pipe -> (
          match Itb3.save pipe with
          | exception exn ->
              err_line (Printf.sprintf "Save(%s): %s" profile (status_detail exn));
              (try Itb3.close pipe with Itb3.ITB_error _ -> ());
              None
          | blob when cfg.blob_mode <> 2 ->
              log_pipeline_initialised profile blob;
              Some (pipe, blob)
          | blob ->
              (* The sizing mode is not an Opts knob: the Init blob is
                 edited and the pipeline reopened from it, so the
                 retained blob (the one blob-cycle reopens from)
                 carries the edited mode. *)
              (try Itb3.close pipe with Itb3.ITB_error _ -> ());
              if not (edit_inner_blob_mode blob 2) then (
                err_line "rewrite blob mode: inner blob mode field not found";
                None)
              else (
                match Itb3.load blob with
                | exception exn ->
                    err_line (Printf.sprintf "reload Mode 2 blob: %s" (status_detail exn));
                    None
                | reloaded ->
                    log_pipeline_initialised profile blob;
                    Some (reloaded, blob))))

(* ---------------------------------------------------------------- *)
(* Run                                                              *)
(* ---------------------------------------------------------------- *)

let run argv =
  let rc, cfg = parse_flags argv in
  if rc = 1 then 0
  else if rc <> 0 then 2
  else begin
    let r = make_run_state cfg in

    (* Runtime shaping. A long run under allocation churn grows the Go
       heap inside the shared library without bound unless a soft limit
       paces the collector, so a limit is always in force: an explicit
       --memlimit is set as given, and auto caps the heap only when the
       runtime reports no limit at all (a limit already installed from
       the environment is left standing). The GC percentage and
       GOMAXPROCS are set only when their flag is non-zero -- a zero
       flag skips the setter rather than calling it with zero, because
       zero is a real value to the GC-percent setter, and a call would
       clobber whatever the environment installed. All of it lands
       before any Pipeline exists so the baselines are taken under the
       shaped runtime. *)
    if cfg.memlimit_auto then begin
      if Itb3.memory_limit () = Int64.max_int then
        Itb3.set_memory_limit (Int64.to_int cfg.memlimit)
    end
    else Itb3.set_memory_limit (Int64.to_int cfg.memlimit);
    cfg.memlimit <- Itb3.memory_limit ();
    if cfg.gogc > 0 then Itb3.set_gc_percent cfg.gogc;
    if cfg.gomaxprocs > 0 then ignore (Itb3.set_gomaxprocs cfg.gomaxprocs);

    log_line
      (Printf.sprintf
         "start: duration=%s iterations=%d goroutines=%d workers=%d concurrency=%s \
          shape=%s hash=%s mac=%s payload=%s memlimit=%s parallax=%s wrapper=%s"
         (Size.human_duration cfg.duration_ns)
         cfg.iterations cfg.workers_requested cfg.workers concurrency
         (Worker.shape_name cfg.shape) cfg.hash cfg.mac
         (Size.human_bytes cfg.payload)
         (Size.human_bytes (Int64.to_int cfg.memlimit))
         (on_off cfg.parallax) (on_off cfg.wrapper));
    log_line
      (Printf.sprintf
         "overrides: profile=\"%s\" key-bits=%d nonce-bits=%d chunk-size=%s \
          barrier-fill=%d gomaxprocs=%d rekey-every=%d blob-cycle-every=%d \
          payload-mode=%s seed=%Lu json-output=%s%s%s"
         cfg.profile cfg.key_bits cfg.nonce_bits
         (Size.human_bytes cfg.chunk_size)
         cfg.barrier_fill cfg.gomaxprocs cfg.rekey_every cfg.blob_cycle_every
         (Payload.payload_mode_name cfg.payload_mode)
         cfg.seed
         (if cfg.json_output then "true" else "false")
         (if cfg.blob_mode <> 1 then Printf.sprintf " blob-mode=%d" cfg.blob_mode else "")
         (if cfg.drbg = "" then "" else " drbg=" ^ cfg.drbg));
    log_line
      (Printf.sprintf "policy: microbatch-tiers=%s hashpool-starters=%s"
         (policy_label "ITB_MICROBATCH_TIERS")
         (policy_label "ITB_HASHPOOL_STARTERS"));

    (* Pipeline construction -- one handle per exercised shape. stream
       and stream_one_shot share the streaming handle. *)
    r.stream_profile <- (if cfg.profile = "" then default_stream_profile else cfg.profile);
    r.msg_profile <- (if cfg.profile = "" then default_message_profile else cfg.profile);
    let built_ok = ref true in
    if cfg.shape = Stream || cfg.shape = Stream_one_shot || cfg.shape = Both then (
      match build_pipeline cfg r.stream_profile with
      | None -> built_ok := false
      | Some (pipe, blob) ->
          r.stream_pipe <- Some pipe;
          r.stream_blob <- blob);
    if !built_ok && (cfg.shape = Message || cfg.shape = Both) then (
      match build_pipeline cfg r.msg_profile with
      | None -> built_ok := false
      | Some (pipe, blob) ->
          r.msg_pipe <- Some pipe;
          r.msg_blob <- blob);
    if not !built_ok then 1
    else begin
      (* Allocation posture. The worker's plaintext is allocated once
         and held for the whole run (rotating mode refills it in place
         per iteration); the pump accumulators and the drain slice live
         inside the worker and are reused across iterations; the
         message and one-shot outputs are the buffers the binding
         returns per call and the collector reclaims them when the
         iteration drops them. Under the default fixed CSPRNG mode
         every worker's buffer is distinct, so cross-worker data
         crossover is detectable; pattern modes trade that property for
         content edge-case coverage. *)
      let workers =
        Array.init cfg.workers (fun i ->
            let w = make_worker i in
            w.payload_mode <- cfg.payload_mode;
            w.seeded <- cfg.seed <> 0L;
            w.rng <- Payload.seed_worker cfg.seed i;
            w.plaintext <- Bytes.create cfg.payload;
            w)
      in
      r.workers <- workers;
      let fill_ok = ref true in
      Array.iter
        (fun w ->
          match Payload.fill_payload w.plaintext cfg.payload_mode w.seeded w.rng with
          | Some advanced -> w.rng <- advanced
          | None -> fill_ok := false)
        workers;
      if not !fill_ok then begin
        err_line "payload fill: csprng";
        1
      end
      else begin
        r.pool_warmup <- Summary.pool_snapshot ();
        r.pool_steady <- Array.copy r.pool_warmup;
        if Array.length r.pool_warmup = 0 then begin
          err_line "pool snapshot alloc failed";
          1
        end
        else begin
          install_signals ();
          let w = workers.(0) in

          (* Warmup barrier. The worker runs one iteration before the
             clock starts, so the first-call costs (pool warm-up, lazy
             kernel dispatch, page faults on the payload buffer) are
             outside the measured window, and the RSS and pool
             baselines taken here describe a process that has already
             run the whole cipher path once. The rendezvous the
             contract places after that iteration has one party in this
             mode, so it degenerates into the straight line below --
             the ordering it exists to impose is already the only
             ordering available. *)
          let warmup_start = Size.now_ns () in
          let warmup_ok = Worker.warmup r w in
          let rss_warmup, rss_peak = Summary.read_rss () in
          r.rss_warmup <- rss_warmup;
          r.rss_peak <- rss_peak;
          r.pool_warmup <- Summary.pool_snapshot ();
          let warmup_ns = Size.now_ns () - warmup_start in
          log_line
            (Printf.sprintf "warmup: %d workers x 1 iter completed in %s (baseline rss=%s)"
               cfg.workers
               (Size.human_duration ((warmup_ns + 50_000_000) / 100_000_000 * 100_000_000))
               (Size.human_bytes r.rss_warmup));

          r.start_ns <- Size.now_ns ();
          r.finish_ns <- r.start_ns;
          if warmup_ok then Worker.run_worker r w stop_requested;
          let elapsed_ns = r.finish_ns - r.start_ns in
          let rss_final, peak = Summary.read_rss () in
          r.rss_final <- rss_final;
          r.rss_peak <- max r.rss_peak peak;
          r.pool_steady <- Summary.pool_snapshot ();

          if cfg.memprofile <> "" then (
            match Itb3.write_heap_profile cfg.memprofile with
            | () ->
                log_line
                  (Printf.sprintf "memprofile: heap profile written to %s" cfg.memprofile)
            | exception Itb3.ITB_error (_, message) ->
                err_line (Printf.sprintf "memprofile: %s" message));

          let rc = Summary.final_summary r elapsed_ns in
          Option.iter (fun p -> try Itb3.close p with Itb3.ITB_error _ -> ()) r.stream_pipe;
          Option.iter (fun p -> try Itb3.close p with Itb3.ITB_error _ -> ()) r.msg_pipe;
          rc
        end
      end
    end
  end

let () =
  restore_sigpipe ();
  exit (run (Array.sub Sys.argv 1 (Array.length Sys.argv - 1)))
