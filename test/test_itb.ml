(* Surface parity checks for the OCaml binding; the deep suite lives
   in Go under the shipped tree. *)

(* Deterministic non-trivial payload (xorshift fill). *)
let payload n seed =
  let out = Bytes.create n in
  let x = ref (Int64.logor (Int64.of_int seed) 1L) in
  for i = 0 to n - 1 do
    x := Int64.logxor !x (Int64.shift_left !x 13);
    x := Int64.logxor !x (Int64.shift_right_logical !x 7);
    x := Int64.logxor !x (Int64.shift_left !x 17);
    Bytes.set out i (Char.chr (Int64.to_int (Int64.logand !x 0xFFL)))
  done;
  out

let check_status expected f =
  match f () with
  | exception Itb3.ITB_error (st, _) when st = expected -> ()
  | exception Itb3.ITB_error (st, msg) ->
      Alcotest.failf "expected status %d, got %d (%s)" expected st msg
  | _ -> Alcotest.failf "expected ITB_error with status %d, call succeeded" expected

let test_version () =
  let v = Itb3.version () in
  Alcotest.(check bool) "version non-empty" true (String.length v > 0);
  (match String.index_opt v '.' with
  | Some _ -> ()
  | None -> Alcotest.failf "version %S has no dot" v)

let test_drbg_auto_tier () =
  let t = Itb3.drbg_auto_tier () in
  Alcotest.(check bool)
    (Printf.sprintf "drbg auto tier %S is a fill cipher" t)
    true
    (t = "aes-256-ctr" || t = "chacha20")

let test_profiles_list () =
  let profiles = Itb3.profiles () in
  Alcotest.(check bool) "has singlemsg mac" true
    (List.mem "singlemsg-triple-mac-v1" profiles);
  Alcotest.(check bool) "has streaming noaead" true
    (List.mem "streaming-noaead-triple-v1" profiles);
  Alcotest.(check (list string)) "sorted" (List.sort compare profiles) profiles;
  (* Every listed profile resolves and initialises on the Go side. *)
  List.iter
    (fun p ->
      Alcotest.(check bool) (p ^ " lookup carries the name") true
        (String.length (Itb3.lookup p) > 0);
      let pipe = Itb3.create p () in
      Alcotest.(check bool)
        (p ^ " blob non-empty") true
        (Bytes.length (Itb3.save pipe) > 0);
      Itb3.close pipe)
    profiles

let test_message_round_trip () =
  let sender = Itb3.create "singlemsg-triple-mac-v1" () in
  let receiver = Itb3.load (Itb3.save sender) in
  List.iter
    (fun size ->
      let plain = payload size size in
      let wire = Itb3.encrypt_message sender plain in
      Alcotest.(check bool) "wire differs from plaintext" false (Bytes.equal plain wire);
      let back = Itb3.decrypt_message receiver wire in
      Alcotest.(check bool)
        (Printf.sprintf "message round trip @%d" size)
        true (Bytes.equal plain back))
    [ 4 * 1024; 256 * 1024 ]

let test_stream_round_trip () =
  let sender = Itb3.create "streaming-noaead-triple-v1" () in
  let receiver = Itb3.load (Itb3.save sender) in
  let n = (3 * 1024 * 1024) + 17 in
  let plain = payload n 42 in
  let enc = Itb3.encrypt_stream sender in
  (* Feed in uneven slices to exercise incremental writes. *)
  let off = ref 0 in
  List.iter
    (fun upto ->
      Itb3.write enc (Bytes.sub plain !off (upto - !off));
      off := upto)
    [ 1_000_000; 1_700_001; n ];
  let wire = Itb3.drain_all enc in
  Alcotest.(check bool) "wire non-empty" true (Bytes.length wire > 0);
  let dec = Itb3.decrypt_stream receiver in
  Itb3.write dec wire;
  let back = Itb3.drain_all dec in
  Alcotest.(check bool)
    (Printf.sprintf "stream round trip (%d vs %d bytes)" (Bytes.length plain)
       (Bytes.length back))
    true (Bytes.equal plain back)

let test_stream_incremental_read () =
  let sender = Itb3.create "streaming-aead-triple-mac-v1" () in
  let receiver = Itb3.load (Itb3.save sender) in
  let plain = payload ((2 * 1024 * 1024) + 3) 7 in
  let enc = Itb3.encrypt_stream sender in
  (* Bounded-memory loop: feed a slice, drain available wire, repeat. *)
  let wire = Buffer.create (1 lsl 20) in
  let slice = 1 lsl 20 in
  let off = ref 0 in
  while !off < Bytes.length plain do
    let len = min slice (Bytes.length plain - !off) in
    Itb3.write enc (Bytes.sub plain !off len);
    off := !off + len;
    let rec drain () =
      let chunk, _ = Itb3.read enc in
      if Bytes.length chunk > 0 then (
        Buffer.add_bytes wire chunk;
        drain ())
    in
    drain ()
  done;
  Buffer.add_bytes wire (Itb3.drain_all enc);
  let dec = Itb3.decrypt_stream receiver in
  Itb3.write dec (Buffer.to_bytes wire);
  let back = Itb3.drain_all dec in
  Alcotest.(check bool) "incremental round trip" true (Bytes.equal plain back)

let test_bad_profile_maps_to_unknown_profile () =
  (* Status 13 = UNKNOWN_PROFILE, on create and on lookup alike. *)
  check_status 13 (fun () -> Itb3.create "no-such-profile" ());
  check_status 13 (fun () -> Itb3.lookup "no-such-profile")

let test_negative_max_workers_opts_is_clamped () =
  let pipe = Itb3.create "singlemsg-triple-mac-v1" ~opts:[ ("maxWorkers", "-1") ] () in
  Alcotest.(check bool) "init with maxWorkers=-1" true (Bytes.length (Itb3.save pipe) > 0);
  Itb3.close pipe

let test_tampered_wire_fails_decrypt () =
  let sender = Itb3.create "singlemsg-triple-mac-v1" () in
  let receiver = Itb3.load (Itb3.save sender) in
  let wire = Itb3.encrypt_message sender (payload (8 * 1024) 3) in
  (* XOR a 64-byte span so the corruption is guaranteed to hit data
     bits (a single flipped bit can land in a noise-bit position the
     decode path ignores). *)
  let mid = Bytes.length wire / 2 in
  for i = mid to mid + 63 do
    Bytes.set wire i (Char.chr (Char.code (Bytes.get wire i) lxor 0xFF))
  done;
  (* Status 10 = MAC_FAILURE. *)
  check_status 10 (fun () -> Itb3.decrypt_message receiver wire)

let test_closed_pipeline_reports_triple_closed () =
  let pipe = Itb3.create "singlemsg-triple-mac-v1" () in
  Itb3.close pipe;
  Itb3.close pipe;
  (* idempotent *)
  (* Status 25 = TRIPLE_CLOSED. *)
  check_status 25 (fun () -> Itb3.encrypt_message pipe (Bytes.of_string "payload"))

let test_large_plaintext_round_trip () =
  (* Pattern P1: the pre-allocated output buffer plus a single retry
     gated on strict len > cap must cover a > 1 MiB payload. *)
  let sender = Itb3.create "singlemsg-triple-nomac-v1" () in
  let receiver = Itb3.load (Itb3.save sender) in
  let plain = payload ((1 lsl 20) + 4321) 9 in
  let wire = Itb3.encrypt_message sender plain in
  let back = Itb3.decrypt_message receiver wire in
  Alcotest.(check bool)
    (Printf.sprintf "large round trip (%d vs %d bytes)" (Bytes.length plain)
       (Bytes.length back))
    true (Bytes.equal plain back)

let test_rekey_refreshes_blob () =
  let sender = Itb3.create "singlemsg-triple-mac-v1" () in
  let old_blob = Itb3.save sender in
  let rotated = Itb3.rekey ~perm:(Bytes.make 32 '\x01') ~wrap:(Bytes.make 32 '\x02') sender in
  Alcotest.(check bool) "blob refreshed" false (Bytes.equal old_blob rotated);
  Alcotest.(check bool) "save reports the rotated blob" true
    (Bytes.equal rotated (Itb3.save sender));
  let receiver = Itb3.load rotated in
  let plain = Bytes.of_string "after rekey" in
  let wire = Itb3.encrypt_message sender plain in
  Alcotest.(check bool) "post-rekey round trip" true
    (Bytes.equal plain (Itb3.decrypt_message receiver wire))

(* A width-256 mixed profile record in profile JSON form: an 8-entry
   hashes constellation, layers off. *)
let mixed_profile =
  "{\"mode\":\"singlemsg-nomac\",\"width\":256,"
  ^ "\"hashes\":[\"blake3\",\"blake2s\",\"areion256\",\"blake2b256\","
  ^ "\"chacha20\",\"blake3\",\"blake2s\",\"areion256\"],"
  ^ "\"keybits\":1024,\"wrapper\":false,\"parallax\":false}"

let contains hay needle =
  let n = String.length needle and h = String.length hay in
  let rec go i = i + n <= h && (String.sub hay i n = needle || go (i + 1)) in
  go 0

let test_register_round_trip () =
  Itb3.register ~name:"test-profile-v1" ~profile:mixed_profile;
  let sender = Itb3.create "test-profile-v1" () in
  let receiver = Itb3.load (Itb3.save sender) in
  let plain = payload (8 * 1024) 11 in
  let wire = Itb3.encrypt_message sender plain in
  Alcotest.(check bool) "registered-profile round trip" true
    (Bytes.equal plain (Itb3.decrypt_message receiver wire));
  (* The registered record reads back with its name filled in. *)
  let looked = Itb3.lookup "test-profile-v1" in
  Alcotest.(check bool) "lookup carries the name" true
    (contains looked "\"name\":\"test-profile-v1\"");
  Alcotest.(check bool) "lookup carries the hashes" true
    (contains looked "\"hashes\":[\"blake3\",\"blake2s\"");
  (* Status 26 = PROFILE_EXISTS. *)
  check_status 26 (fun () -> Itb3.register ~name:"test-profile-v1" ~profile:mixed_profile);
  (* A non-empty name inside the record must equal the argument
     (status 4 = BAD_INPUT). *)
  check_status 4 (fun () ->
      Itb3.register ~name:"test-profile-mismatch"
        ~profile:
          ("{\"name\":\"other\",\"mode\":\"singlemsg-nomac\",\"width\":512,"
          ^ "\"hash\":\"areion512\",\"keybits\":1024,\"wrapper\":false,\"parallax\":false}"));
  Itb3.close receiver;
  Itb3.close sender

let test_save_load_round_trip () =
  let sender = Itb3.create "singlemsg-triple-mac-v1" () in
  let blob = Itb3.save sender in
  Alcotest.(check bool) "save is stable" true (Bytes.equal blob (Itb3.save sender));
  let receiver = Itb3.load blob in
  let plain = Bytes.of_string "in-memory" in
  Alcotest.(check bool) "in-memory round trip" true
    (Bytes.equal plain (Itb3.decrypt_message receiver (Itb3.encrypt_message sender plain)));
  Alcotest.(check bool) "load retains the blob bytes" true (Bytes.equal blob (Itb3.save receiver));
  (* Load with master overrides equals a sender rekey. *)
  let perm = Bytes.make 32 '\x31' and wrap = Bytes.make 32 '\x32' in
  let rotated = Itb3.load ~perm ~wrap blob in
  Alcotest.(check bool) "master overrides rotate the blob" false
    (Bytes.equal blob (Itb3.save rotated));
  ignore (Itb3.rekey ~perm ~wrap sender);
  Alcotest.(check bool) "override round trip" true
    (Bytes.equal plain (Itb3.decrypt_message rotated (Itb3.encrypt_message sender plain)));
  Itb3.close rotated;
  Itb3.close receiver;
  Itb3.close sender

let test_inspect_carries_recipe_and_inspection_fields () =
  (* inspect carries the registry recipe plus the blob-only
     nonce_bits / barrier_fill inspection fields; lookup returns just
     the recipe. *)
  let sender = Itb3.create "singlemsg-triple-mac-v1" () in
  let inspected = Itb3.inspect (Itb3.save sender) in
  let looked = Itb3.lookup "singlemsg-triple-mac-v1" in
  Alcotest.(check bool) "inspect carries the name" true
    (contains inspected "\"name\":\"singlemsg-triple-mac-v1\"");
  Alcotest.(check bool) "inspect carries the mode" true
    (contains inspected "\"mode\":\"singlemsg-mac\"");
  Alcotest.(check bool) "inspect carries nonce_bits" true
    (contains inspected "\"nonce_bits\":");
  Alcotest.(check bool) "inspect carries barrier_fill" true
    (contains inspected "\"barrier_fill\":");
  Alcotest.(check bool) "lookup carries the name" true
    (contains looked "\"name\":\"singlemsg-triple-mac-v1\"");
  Alcotest.(check bool) "lookup omits nonce_bits" false
    (contains looked "\"nonce_bits\":");
  Alcotest.(check bool) "lookup omits barrier_fill" false
    (contains looked "\"barrier_fill\":");
  (* Status 4 = BAD_INPUT. *)
  check_status 4 (fun () -> Itb3.inspect (Bytes.of_string "not a blob"));
  Itb3.close sender

let test_save_f_load_f_round_trip () =
  let path = Filename.concat (Filename.get_temp_dir_name ())
      (Printf.sprintf "itb-ocaml-persist-%d.blob" (Unix.getpid ())) in
  let sender = Itb3.create "streaming-aead-triple-mac-v1" () in
  Itb3.save_f sender path;
  Alcotest.(check int) "mode 0600" 0o600 ((Unix.stat path).Unix.st_perm land 0o777);
  let receiver = Itb3.load_f path in
  let plain = Bytes.of_string "on-disk" in
  Alcotest.(check bool) "on-disk round trip" true
    (Bytes.equal plain
       (Itb3.decrypt_stream_one_shot receiver (Itb3.encrypt_stream_one_shot sender plain)));
  Sys.remove path;
  (* Status 4 = BAD_INPUT. *)
  check_status 4 (fun () -> Itb3.load_f path);
  Itb3.close receiver;
  Itb3.close sender

let test_max_workers_clamps () =
  let sender = Itb3.create "singlemsg-triple-mac-v1" () in
  Itb3.max_workers sender 2;
  Itb3.max_workers sender (-1);
  Itb3.max_workers sender 100_000;
  let receiver = Itb3.load (Itb3.save sender) in
  Itb3.max_workers receiver 1;
  let plain = Bytes.of_string "workers" in
  Alcotest.(check bool) "workers round trip" true
    (Bytes.equal plain (Itb3.decrypt_message receiver (Itb3.encrypt_message sender plain)));
  Itb3.close receiver;
  (* Status 25 = TRIPLE_CLOSED. *)
  check_status 25 (fun () -> Itb3.save receiver);
  check_status 25 (fun () -> Itb3.max_workers receiver 2);
  Itb3.close sender

let test_one_shot_stream_round_trip () =
  let sender = Itb3.create "streaming-noaead-triple-v1" () in
  let receiver = Itb3.load (Itb3.save sender) in
  let plain = payload (4 * 1024) 13 in
  let wire = Itb3.encrypt_stream_one_shot sender plain in
  Alcotest.(check bool) "wire differs from plaintext" false (Bytes.equal plain wire);
  let back = Itb3.decrypt_stream_one_shot receiver wire in
  Alcotest.(check bool) "one-shot stream round trip" true (Bytes.equal plain back);
  (* Wire parity: an incremental session decrypts the one-shot wire. *)
  let dec = Itb3.decrypt_stream receiver in
  Itb3.write dec wire;
  let back2 = Itb3.drain_all dec in
  Alcotest.(check bool) "session decrypts one-shot wire" true
    (Bytes.equal plain back2);
  Itb3.close receiver;
  Itb3.close sender

let test_message_into_round_trip () =
  let sender = Itb3.create "singlemsg-triple-nomac-v1" () in
  let receiver = Itb3.load (Itb3.save sender) in
  let plain = payload (256 * 1024) 17 in
  (* One grow-only pair of caller buffers reused across both calls. *)
  let wire_buf = Bytes.create (Itb3.message_out_cap (Bytes.length plain)) in
  let n = Itb3.encrypt_message_into sender plain wire_buf in
  Alcotest.(check bool) "wire length positive" true (n > 0);
  let wire = Bytes.sub wire_buf 0 n in
  Alcotest.(check bool) "into wire matches allocating wire length" true
    (Bytes.length (Itb3.encrypt_message sender plain) > 0);
  let back_buf = Bytes.create (Bytes.length plain + 131072) in
  let m = Itb3.decrypt_message_into receiver wire back_buf in
  Alcotest.(check bool)
    (Printf.sprintf "message _into round trip (%d vs %d bytes)"
       (Bytes.length plain) m)
    true
    (m = Bytes.length plain && Bytes.equal plain (Bytes.sub back_buf 0 m));
  Itb3.close receiver;
  Itb3.close sender

let test_message_into_undersized_dst_reports_buffer_too_small () =
  (* The _into entries do not retry -- the caller owns capacity
     planning; an undersized dst surfaces as BUFFER_TOO_SMALL. *)
  let sender = Itb3.create "singlemsg-triple-nomac-v1" () in
  let tiny = Bytes.create 16 in
  (* Status 5 = BUFFER_TOO_SMALL. *)
  check_status 5 (fun () ->
      Itb3.encrypt_message_into sender (payload 4096 19) tiny);
  Itb3.close sender

let test_into_cap_guard_raises_invalid_argument () =
  let pipe = Itb3.create "streaming-noaead-triple-v1" () in
  let enc = Itb3.encrypt_stream pipe in
  let buf = Bytes.create 64 in
  (match Itb3.read_into enc buf (Bytes.length buf + 1) with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "oversized cap accepted by read_into");
  (match Itb3.write_sub enc buf 1 (Bytes.length buf) with
  | exception Invalid_argument _ -> ()
  | _ -> Alcotest.fail "escaping range accepted by write_sub");
  (* The stream is still usable after the two argument-guard rejections;
     feed real bytes so the cleanup drain does not hit Go's uniform
     empty-input policy (ErrEmptyInput -> ITB_error 4). *)
  Itb3.write_sub enc buf 0 (Bytes.length buf);
  ignore (Itb3.drain_all enc);
  Itb3.close pipe

let test_read_into_partial_drains () =
  let sender = Itb3.create "streaming-noaead-triple-v1" () in
  let receiver = Itb3.load (Itb3.save sender) in
  let plain = payload ((1 lsl 20) + 331) 23 in
  let enc = Itb3.encrypt_stream sender in
  (* Feed via zero-copy sub-ranges. *)
  let slice = 300_000 in
  let off = ref 0 in
  while !off < Bytes.length plain do
    let len = min slice (Bytes.length plain - !off) in
    Itb3.write_sub enc plain !off len;
    off := !off + len
  done;
  Itb3.end_ enc;
  (* Drain through a deliberately small reusable buffer so the wire
     crosses many partial read_into calls. *)
  let small = Bytes.create 4096 in
  let wire = Buffer.create (1 lsl 20) in
  let rec drain () =
    let n, finished = Itb3.read_into enc small (Bytes.length small) in
    Buffer.add_subbytes wire small 0 n;
    if not finished then drain ()
  in
  drain ();
  let dec = Itb3.decrypt_stream receiver in
  Itb3.write dec (Buffer.to_bytes wire);
  let back = Itb3.drain_all dec in
  Alcotest.(check bool) "partial-drain round trip" true (Bytes.equal plain back);
  Itb3.close receiver;
  Itb3.close sender


let test_runtime_observation_handles () =
  (* GOMAXPROCS: the setter reports the previous value, and the query
     form (n <= 0) leaves it where the set put it. *)
  let previous = Itb3.set_gomaxprocs 2 in
  Alcotest.(check int) "query reports the value just set" 2 (Itb3.set_gomaxprocs 0);
  ignore (Itb3.set_gomaxprocs previous);
  (* The heap limit and the GC percentage are readable through their
     own query entries; a run has a limit in force once one is set. *)
  Itb3.set_memory_limit (512 * 1024 * 1024);
  Alcotest.(check bool) "heap limit readable" true
    (Itb3.memory_limit () = 536870912L);
  Alcotest.(check bool) "gc percent readable" true (Itb3.gc_percent () > 0);
  (* The pool-counter vector is sized from the library's own length
     query; slot 0 carries the hash-array tier count and the layout
     runs 1 + 5t + 8 slots. *)
  let n = Itb3.pool_stats_len () in
  Alcotest.(check bool) "pool slot count positive" true (n > 0);
  let stats = Itb3.pool_stats () in
  Alcotest.(check int) "snapshot fills every slot" n (Array.length stats);
  let tiers = stats.(0) in
  Alcotest.(check bool) "at least one tier" true (tiers >= 1);
  Alcotest.(check int) "slot layout is 1 + 5t + 8" n ((1 + (5 * tiers)) + 8);
  (* Counters are monotone totals since library load, so a second
     snapshot never goes backwards. *)
  let again = Itb3.pool_stats () in
  Array.iteri
    (fun i v -> Alcotest.(check bool) "counters monotone" true (again.(i) >= v))
    stats

let test_heap_profile_written () =
  let path = Filename.temp_file "itb-heap" ".prof" in
  Fun.protect
    ~finally:(fun () -> try Sys.remove path with Sys_error _ -> ())
    (fun () ->
      Itb3.write_heap_profile path;
      let ic = open_in_bin path in
      Fun.protect
        ~finally:(fun () -> close_in ic)
        (fun () ->
          (* A pprof payload is a gzip-wrapped protobuf, so the first
             two bytes are the gzip magic. *)
          Alcotest.(check bool) "profile non-empty" true (in_channel_length ic > 0);
          Alcotest.(check int) "gzip magic byte 0" 0x1f (input_byte ic);
          Alcotest.(check int) "gzip magic byte 1" 0x8b (input_byte ic)));
  (* A path the library cannot open surfaces as a diagnostic rather
     than a silent success. *)
  check_status 4 (fun () ->
      Itb3.write_heap_profile (Filename.concat (Filename.get_temp_dir_name ()) "no-such-dir/heap.prof"))

let test_hash_names_registry () =
  let names = Itb3.hash_names () in
  Alcotest.(check bool) "registry non-empty" true (names <> []);
  Alcotest.(check bool) "has areion512" true (List.mem "areion512" names);
  Alcotest.(check bool) "has aesitb128" true (List.mem "aesitb128" names);
  Alcotest.(check bool) "rejects a non-primitive" false
    (List.mem "definitely-not-a-primitive" names);
  (* Every enumerated name is accepted by Init as an inner hash, which
     is what the enumeration is for. *)
  List.iter
    (fun name ->
      let pipe = Itb3.create "singlemsg-triple-nomac-v1" ~opts:[ ("innerHash", name) ] () in
      let record = Itb3.inspect (Itb3.save pipe) in
      Alcotest.(check bool)
        (name ^ " reaches the record")
        true
        (let needle = Printf.sprintf "\"hash\":\"%s\"" name in
         let rec find i =
           if i + String.length needle > String.length record then false
           else if String.sub record i (String.length needle) = needle then true
           else find (i + 1)
         in
         find 0);
      Itb3.close pipe)
    names

let test_long_diagnostic_survives_the_retry () =
  (* The diagnostic fetch guesses a buffer and retries on the
     short-buffer return. A sentence longer than that guess is the only
     thing that exercises the retry, and the caller's own data is what
     makes one: the library quotes the offending opts value back in
     full. *)
  let long = String.make 700 'z' in
  match Itb3.create "singlemsg-triple-mac-v1" ~opts:[ ("innerHash", long) ] () with
  | _ -> Alcotest.fail "expected Init to reject a 700-character primitive name"
  | exception Itb3.ITB_error (_, msg) ->
      Alcotest.(check bool)
        (Printf.sprintf "diagnostic kept its full %d bytes" (String.length msg))
        true
        (String.length msg > 512);
      Alcotest.(check bool) "diagnostic carries the offending value" true
        (let rec find i =
           if i + String.length long > String.length msg then false
           else if String.sub msg i (String.length long) = long then true
           else find (i + 1)
         in
         find 0)

let test_drbg_round_trip () =
  List.iter
    (fun name ->
      let sender = Itb3.create "singlemsg-triple-mac-v1" ~opts:[ ("drbg", name) ] () in
      let receiver = Itb3.load (Itb3.save sender) in
      let plain = Bytes.of_string ("drbg " ^ name) in
      Alcotest.(check bool) (name ^ " round trip") true
        (Bytes.equal plain
           (Itb3.decrypt_message receiver (Itb3.encrypt_message sender plain)));
      let back = Bytes.of_string ("reverse " ^ name) in
      Alcotest.(check bool) (name ^ " reverse round trip") true
        (Bytes.equal back
           (Itb3.decrypt_message sender (Itb3.encrypt_message receiver back)));
      Itb3.close receiver;
      Itb3.close sender)
    [ "csprng"; "aesitb128" ]

let test_drbg_inspect_default_and_unknown () =
  let sender = Itb3.create "singlemsg-triple-mac-v1" ~opts:[ ("drbg", "csprng") ] () in
  Alcotest.(check bool) "inspect carries drbg" true
    (contains (Itb3.inspect (Itb3.save sender)) "\"drbg\":\"csprng\"");
  Itb3.close sender;
  (* With no drbg set the record carries no drbg key, and no shipped
     profile names one. *)
  let plain = Itb3.create "singlemsg-triple-mac-v1" () in
  Alcotest.(check bool) "default inspect omits drbg" false
    (contains (Itb3.inspect (Itb3.save plain)) "\"drbg\":");
  Itb3.close plain;
  Alcotest.(check bool) "lookup omits drbg" false
    (contains (Itb3.lookup "singlemsg-triple-mac-v1") "\"drbg\":");
  (* Status 12 = RECIPE_PRIMITIVE_UNKNOWN. *)
  match Itb3.create "singlemsg-triple-mac-v1" ~opts:[ ("drbg", "nope") ] () with
  | exception Itb3.ITB_error (12, msg) ->
      Alcotest.(check bool) "diagnostic names the token" true (contains msg "nope")
  | exception Itb3.ITB_error (st, msg) ->
      Alcotest.failf "expected status 12, got %d (%s)" st msg
  | _ -> Alcotest.fail "expected ITB_error with status 12, call succeeded"

(* Removes a "key":value, member with a scalar value from a flat JSON
   object rendering; the record is left unchanged when the key is
   absent. *)
let drop_scalar_key record key =
  let needle = "\"" ^ key ^ "\":" in
  let n = String.length record and k = String.length needle in
  let rec find i =
    if i + k > n then None
    else if String.sub record i k = needle then Some i
    else find (i + 1)
  in
  match find 0 with
  | None -> record
  | Some i ->
      let j = match String.index_from_opt record (i + k) ',' with
        | Some c -> c + 1
        | None -> n
      in
      String.sub record 0 i ^ String.sub record j (n - j)

let test_drbg_register_copy () =
  let sender = Itb3.create "singlemsg-triple-mac-v1" ~opts:[ ("drbg", "csprng") ] () in
  (* The inspection-only fields are dropped; drbg is a recipe field and
     stays in the registered copy. *)
  let record =
    List.fold_left drop_scalar_key
      (Itb3.inspect (Itb3.save sender))
      [ "name"; "nonce_bits"; "barrier_fill"; "container_mode" ]
  in
  Itb3.register ~name:"ocaml-binding-test-drbg-copy" ~profile:record;
  Alcotest.(check bool) "register copy keeps drbg" true
    (contains (Itb3.lookup "ocaml-binding-test-drbg-copy") "\"drbg\":\"csprng\"");
  Itb3.close sender

let () =
  (* Go-runtime pacing caps applied before any cipher work. *)
  Itb3.set_memory_limit (512 * 1024 * 1024);
  Itb3.set_gc_percent 20;
  let case name f = Alcotest.test_case name `Quick f in
  Alcotest.run "itb"
    [
      ( "surface",
        [
          case "version" (fun () -> test_version ());
          case "drbg auto tier" (fun () -> test_drbg_auto_tier ());
          case "profiles list" (fun () -> test_profiles_list ());
        ] );
      ( "message",
        [
          case "round trip" (fun () -> test_message_round_trip ());
          case "large plaintext (P1)" (fun () -> test_large_plaintext_round_trip ());
          case "tampered wire" (fun () -> test_tampered_wire_fails_decrypt ());
        ] );
      ( "stream",
        [
          case "round trip" (fun () -> test_stream_round_trip ());
          case "incremental read" (fun () -> test_stream_incremental_read ());
        ] );
      ( "errors",
        [
          case "bad profile" (fun () -> test_bad_profile_maps_to_unknown_profile ());
          case "negative maxWorkers clamped" (fun () ->
              test_negative_max_workers_opts_is_clamped ());
          case "closed pipeline" (fun () -> test_closed_pipeline_reports_triple_closed ());
        ] );
      ("rekey", [ case "refreshes blob" (fun () -> test_rekey_refreshes_blob ()) ]);
      ( "persist",
        [
          case "save / load round trip" (fun () -> test_save_load_round_trip ());
          case "inspect carries recipe + inspection fields"
            (fun () -> test_inspect_carries_recipe_and_inspection_fields ());
          case "save_f / load_f round trip" (fun () -> test_save_f_load_f_round_trip ());
          case "max_workers clamps" (fun () -> test_max_workers_clamps ());
        ] );
      ( "extensions",
        [
          case "register round-trip" (fun () ->
              test_register_round_trip ());
          case "one-shot stream round-trip" (fun () ->
              test_one_shot_stream_round_trip ());
        ] );
      ( "into",
        [
          case "message _into round trip" (fun () ->
              test_message_into_round_trip ());
          case "undersized dst reports buffer too small" (fun () ->
              test_message_into_undersized_dst_reports_buffer_too_small ());
          case "cap guard raises Invalid_argument" (fun () ->
              test_into_cap_guard_raises_invalid_argument ());
          case "read_into partial drains" (fun () ->
              test_read_into_partial_drains ());
        ] );
      ( "runtime",
        [
          case "observation handles" (fun () -> test_runtime_observation_handles ());
          case "heap profile written" (fun () -> test_heap_profile_written ());
          case "hash registry enumeration" (fun () -> test_hash_names_registry ());
          case "long diagnostic survives the retry" (fun () ->
              test_long_diagnostic_survives_the_retry ());
        ] );
      ( "drbg",
        [
          case "round trip through a loaded blob" (fun () -> test_drbg_round_trip ());
          case "inspect, default and unknown name" (fun () ->
              test_drbg_inspect_default_and_unknown ());
          case "register copy keeps drbg" (fun () -> test_drbg_register_copy ());
        ] );
    ]
