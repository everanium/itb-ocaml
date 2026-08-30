(* Micro-benchmarks for the OCaml binding: encrypt_message (Single
   Message profile) and stream-session encrypt (Streaming Non-AEAD
   profile) throughput at 1 MiB / 16 MiB / 64 MiB. Wall-clock via
   Unix.gettimeofday; output is a fixed-width table:

     bench             size     mb_per_sec
     message           1 MiB    <n>
     ...

   Configuration is driven by environment variables so a side-by-side
   comparison with the root Go bench harness is straightforward:

     ITB_NONCE_BITS      512         shipped secure default
     ITB_KEY_BITS        1024        matches root Go BENCH3.md table
     ITB_WITH_PARALLAX   false       root Go bench runs without parallax
     ITB_WITH_WRAPPER    false       root Go bench runs without the wrapper
     ITB_INNER_HASH      (profile)   opaque hash name
     ITB_MSG_PROFILE     (fallback ITB_PROFILE, then singlemsg-triple-nomac-v1)
     ITB_STREAM_PROFILE  (fallback ITB_PROFILE, then streaming-noaead-triple-v1)
     ITB_BENCH_MIN_SEC   5           per-case wall-clock budget (seconds) *)

(* Per-case iteration floor alongside the wall-clock budget. *)
let bench_min_iters = 3
let sizes = [ 1 lsl 20; 16 lsl 20; 64 lsl 20 ]

let env ?(default = "") name =
  match Sys.getenv_opt name with Some v when v <> "" -> v | _ -> default

let bench_min_seconds =
  match float_of_string_opt (env "ITB_BENCH_MIN_SEC") with
  | Some v when v > 0.0 -> v
  | _ -> 5.0

(* Reads the bench-shape env vars and builds the opts list. Defaults
   match root Go BENCH3.md so numbers are directly comparable. *)
let build_opts () =
  let truthy v = v = "true" || v = "1" in
  let base =
    [
      ("nonceBits", env ~default:"512" "ITB_NONCE_BITS");
      ("keyBits", env ~default:"1024" "ITB_KEY_BITS");
      ("withParallax", if truthy (env "ITB_WITH_PARALLAX") then "true" else "false");
      ("withWrapper", if truthy (env "ITB_WITH_WRAPPER") then "true" else "false");
    ]
  in
  let base =
    match env "ITB_INNER_HASH" with
    | "" -> base
    | inner -> base @ [ ("innerHash", inner) ]
  in
  match env "ITB_MAC_NAME" with
  | "" -> base
  | mac -> base @ [ ("macName", mac) ]

let profile_name shape_env fallback =
  match env shape_env with
  | "" -> (match env "ITB_PROFILE" with "" -> fallback | p -> p)
  | s -> s

let size_label size =
  if size >= 1 lsl 20 then Printf.sprintf "%d MiB" (size lsr 20)
  else Printf.sprintf "%d KiB" (size lsr 10)

(* CSPRNG-fill so plaintext content matches the root Go bench
   (crypto/rand). Not in the timing loop. *)
let random_bytes n =
  let ic = open_in_bin "/dev/urandom" in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () ->
      let buf = Bytes.create n in
      really_input ic buf 0 n;
      buf)

(* Runs [f] until the wall-clock budget is spent (with an iteration
   floor + one untimed warm-up), then prints one table row. *)
let bench_case name size f =
  f ();
  (* warm-up *)
  let start = Unix.gettimeofday () in
  let elapsed = ref 0.0 in
  let iters = ref 0 in
  while !elapsed < bench_min_seconds || !iters < bench_min_iters do
    f ();
    incr iters;
    elapsed := Unix.gettimeofday () -. start
  done;
  let mb = float_of_int size *. float_of_int !iters /. (1024.0 *. 1024.0) in
  Printf.printf "%-17s %-8s %.1f\n%!" name (size_label size) (mb /. !elapsed)

let bench_message () =
  let pipe = Itb.create (profile_name "ITB_MSG_PROFILE" "singlemsg-triple-nomac-v1") ~opts:(build_opts ()) () in
  List.iter
    (fun size ->
      let plain = random_bytes size in
      bench_case "message" size (fun () -> ignore (Itb.encrypt_message pipe plain));
      (* Pre-encrypt one wire outside the decrypt timing loop. *)
      let dec_wire = Itb.encrypt_message pipe plain in
      bench_case "message-dec" size (fun () -> ignore (Itb.decrypt_message pipe dec_wire)))
    sizes;
  Itb.close pipe

let bench_stream () =
  let pipe = Itb.create (profile_name "ITB_STREAM_PROFILE" "streaming-noaead-triple-v1") ~opts:(build_opts ()) () in
  let slice = 1 lsl 20 in
  (* One reusable drain buffer across every iteration: the consumer
     side of a real pump (socket / file sink) reads into a stable
     buffer, so the bench does the same via [read_into] instead of
     allocating a fresh chunk per drain call. The feed side uses
     [write_sub] (zero-copy sub-range) instead of slicing a fresh
     1 MiB buffer per [write]. *)
  let out = Bytes.create slice in
  let out_cap = Bytes.length out in
  List.iter
    (fun size ->
      let plain = random_bytes size in
      bench_case "stream" size (fun () ->
          let enc = Itb.encrypt_stream pipe in
          let off = ref 0 in
          while !off < size do
            let len = min slice (size - !off) in
            Itb.write_sub enc plain !off len;
            off := !off + len;
            (* Drain available output so the spool stays bounded. *)
            let rec drain () =
              let n, _ = Itb.read_into enc out out_cap in
              if n > 0 then drain ()
            in
            drain ()
          done;
          Itb.end_ enc;
          let rec final () =
            let _n, finished = Itb.read_into enc out out_cap in
            if not finished then final ()
          in
          final ());
      (* Pre-encrypt one wire outside the decrypt timing loop. *)
      let parts = Buffer.create (size + 65536) in
      let enc = Itb.encrypt_stream pipe in
      let off = ref 0 in
      while !off < size do
        let len = min slice (size - !off) in
        Itb.write_sub enc plain !off len;
        off := !off + len;
        let rec drain () =
          let n, _ = Itb.read_into enc out out_cap in
          if n > 0 then (Buffer.add_subbytes parts out 0 n; drain ())
        in
        drain ()
      done;
      Itb.end_ enc;
      let rec final () =
        let n, finished = Itb.read_into enc out out_cap in
        if n > 0 then Buffer.add_subbytes parts out 0 n;
        if not finished then final ()
      in
      final ();
      let dec_wire = Buffer.to_bytes parts in
      let dec_size = Bytes.length dec_wire in
      bench_case "stream-dec" size (fun () ->
          let dec = Itb.decrypt_stream pipe in
          let off = ref 0 in
          while !off < dec_size do
            let len = min slice (dec_size - !off) in
            Itb.write_sub dec dec_wire !off len;
            off := !off + len;
            let rec drain () =
              let n, _ = Itb.read_into dec out out_cap in
              if n > 0 then drain ()
            in
            drain ()
          done;
          Itb.end_ dec;
          let rec final () =
            let _n, finished = Itb.read_into dec out out_cap in
            if not finished then final ()
          in
          final ()))
    sizes;
  Itb.close pipe

(* Whole-buffer stream: one FFI round trip through
   Itb.encrypt_stream_one_shot / Itb.decrypt_stream_one_shot per
   iteration. *)
let bench_stream_one_shot () =
  let pipe = Itb.create (profile_name "ITB_STREAM_PROFILE" "streaming-noaead-triple-v1") ~opts:(build_opts ()) () in
  List.iter
    (fun size ->
      let plain = random_bytes size in
      bench_case "stream_one_shot" size
        (fun () -> ignore (Itb.encrypt_stream_one_shot pipe plain));
      (* Pre-encrypt one wire outside the decrypt timing loop. *)
      let dec_wire = Itb.encrypt_stream_one_shot pipe plain in
      bench_case "stream_one_shot-dec" size
        (fun () -> ignore (Itb.decrypt_stream_one_shot pipe dec_wire)))
    sizes;
  Itb.close pipe

let () =
  (* Bench-scale allocation churn leaks Go scratch heap unboundedly
     without a soft memory cap + aggressive GC. *)
  Itb.set_memory_limit (512 * 1024 * 1024);
  Itb.set_gc_percent 20;
  Printf.printf "%-17s %-8s %s\n%!" "bench" "size" "mb_per_sec";
  bench_message ();
  bench_stream ();
  bench_stream_one_shot ()
