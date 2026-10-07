(* The final summary in both renderings, and the two measurements it
   folds in that are not per-worker counters: the process resident set
   and the shared library's pool counters. *)

open Decls

(* ---------------------------------------------------------------- *)
(* Resident set                                                     *)
(* ---------------------------------------------------------------- *)

(* Parses one "Vm...:   1234 kB" line of /proc/self/status into bytes;
   zero on any parse failure. *)
let status_kb line =
  match String.index_opt line ':' with
  | None -> 0
  | Some colon -> (
      let rest = String.sub line (colon + 1) (String.length line - colon - 1) in
      let fields = String.split_on_char ' ' (String.trim rest) in
      match List.find_opt (fun f -> f <> "") fields with
      | None -> 0
      | Some first -> ( match int_of_string_opt first with None -> 0 | Some kb -> kb * 1024))

(* The process's current resident set and its high-water mark in bytes,
   from /proc/self/status (VmRSS and VmHWM, reported in kB). Both are
   zero on a platform without that file; the figures are informational
   and never enter the verdict. *)
let read_rss () =
  match open_in "/proc/self/status" with
  | exception Sys_error _ -> (0, 0)
  | ic ->
      let current = ref 0 in
      let peak = ref 0 in
      (try
         while true do
           let line = input_line ic in
           if String.length line >= 6 && String.sub line 0 6 = "VmRSS:" then
             current := status_kb line
           else if String.length line >= 6 && String.sub line 0 6 = "VmHWM:" then
             peak := status_kb line
         done
       with End_of_file -> ());
      close_in ic;
      (!current, !peak)

(* ---------------------------------------------------------------- *)
(* Pool counters                                                    *)
(* ---------------------------------------------------------------- *)

(* Pool counters. The shared library keeps process-wide monotonic
   totals at every pool checkout of its cipher core: per hash-array
   tier the starter width, checkouts, constructor misses, regrow
   replacements and bytes allocated; for the scratch byte pool and the
   parallax chunk pool the checkouts, constructor misses, regrows and
   regrow bytes. Two snapshots bracketing the main loop are differenced
   into per-run hit / miss figures that tell whether a pool keeps its
   items warm between calls or evicts them across GC cycles. The slot
   layout is read from the library: slot 0 carries the tier count T,
   tier i occupies the five slots at 1 + 5*i, and the two byte pools
   occupy the eight slots at 1 + 5*T; the vector is sized from the
   binding's length query, never from a constant. *)
let pool_snapshot () = try Itb3.pool_stats () with Itb3.ITB_error _ -> [||]

(* The differenced pool figures of one run. *)
type pool_delta = {
  tiers : int;
  starter : int array;
  get : int array;
  fresh : int array;
  regrow : int array;
  new_bytes : int array;
  buf_pool : int array; (* get, new, regrow, regrow_bytes *)
  chunk_pool : int array;
}

let empty_delta =
  {
    tiers = 0;
    starter = [||];
    get = [||];
    fresh = [||];
    regrow = [||];
    new_bytes = [||];
    buf_pool = [| 0; 0; 0; 0 |];
    chunk_pool = [| 0; 0; 0; 0 |];
  }

let pool_diff warmup steady =
  let n = Array.length steady in
  if n < 9 || Array.length warmup <> n then empty_delta
  else begin
    let tiers = steady.(0) in
    if tiers < 0 || 1 + (5 * tiers) + 8 > n then empty_delta
    else begin
      let starter = Array.make tiers 0 in
      let get = Array.make tiers 0 in
      let fresh = Array.make tiers 0 in
      let regrow = Array.make tiers 0 in
      let new_bytes = Array.make tiers 0 in
      for i = 0 to tiers - 1 do
        let base = 1 + (5 * i) in
        starter.(i) <- steady.(base);
        get.(i) <- steady.(base + 1) - warmup.(base + 1);
        fresh.(i) <- steady.(base + 2) - warmup.(base + 2);
        regrow.(i) <- steady.(base + 3) - warmup.(base + 3);
        new_bytes.(i) <- steady.(base + 4) - warmup.(base + 4)
      done;
      let tail = 1 + (5 * tiers) in
      let slice from = Array.init 4 (fun k -> steady.(from + k) - warmup.(from + k)) in
      { tiers; starter; get; fresh; regrow; new_bytes;
        buf_pool = slice tail; chunk_pool = slice (tail + 4) }
    end
  end

(* Misses over checkouts as a percentage; zero when nothing was checked
   out. *)
let miss_percent miss get =
  if get <= 0 then 0.0 else 100.0 *. float_of_int miss /. float_of_int get

(* The effective GC percentage as the runtime reports it: the query
   form of the setter (a set-and-restore round trip inside the library)
   so the field is the same whether the value came from the flag, the
   environment, or the runtime default. *)
let effective_gogc flag = if flag > 0 then flag else Itb3.gc_percent ()

(* Renders a string as a JSON literal with the escapes JSON requires. *)
let json_string s =
  let out = Buffer.create (String.length s + 2) in
  Buffer.add_char out '"';
  String.iter
    (fun c ->
      match c with
      | '"' -> Buffer.add_string out "\\\""
      | '\\' -> Buffer.add_string out "\\\\"
      | '\n' -> Buffer.add_string out "\\n"
      | '\r' -> Buffer.add_string out "\\r"
      | '\t' -> Buffer.add_string out "\\t"
      | c when Char.code c < 0x20 ->
          Buffer.add_string out (Printf.sprintf "\\u%04x" (Char.code c))
      | c -> Buffer.add_char out c)
    s;
  Buffer.add_char out '"';
  Buffer.contents out

(* One compact object on one line, keys in the contract's order, floats
   with the contract's decimal counts and never in exponent form. *)
let emit_json r elapsed_ns total_iters total_enc total_dec avg_enc avg_dec errors passed
    pd rss_growth gomaxprocs stream_profile msg_profile =
  let cfg = r.cfg in
  let out = Buffer.create 4096 in
  let add = Buffer.add_string out in
  add (Printf.sprintf "{\"duration_seconds\":%.3f" (float_of_int elapsed_ns /. 1e9));
  add (Printf.sprintf ",\"iterations\":%d" total_iters);
  add
    (Printf.sprintf ",\"per_worker_iterations\":[%s]"
       (String.concat ","
          (Array.to_list (Array.map (fun w -> string_of_int w.iters) r.workers))));
  add (Printf.sprintf ",\"bytes_encrypted\":%d" total_enc);
  add (Printf.sprintf ",\"bytes_decrypted\":%d" total_dec);
  add (Printf.sprintf ",\"encrypt_mb_per_sec\":%.1f" (Size.mb_per_sec total_enc avg_enc));
  add (Printf.sprintf ",\"decrypt_mb_per_sec\":%.1f" (Size.mb_per_sec total_dec avg_dec));
  add
    (Printf.sprintf ",\"combined_mb_per_sec\":%.1f"
       (Size.mb_per_sec (total_enc + total_dec) elapsed_ns));
  add (Printf.sprintf ",\"rekeys\":%d" r.rekeys);
  add (Printf.sprintf ",\"blob_cycles\":%d" r.blob_cycles);
  add
    (Printf.sprintf ",\"worker_errors\":[%s]"
       (String.concat "," (List.map json_string errors)));
  add (Printf.sprintf ",\"verdict\":\"%s\"" (if passed then "PASS" else "FAIL"));
  add (Printf.sprintf ",\"shape\":\"%s\"" (Worker.shape_name cfg.shape));
  add (Printf.sprintf ",\"stream_profile\":%s" (json_string stream_profile));
  add (Printf.sprintf ",\"message_profile\":%s" (json_string msg_profile));
  add (Printf.sprintf ",\"hash\":%s" (json_string cfg.hash));
  add (Printf.sprintf ",\"mac\":%s" (json_string cfg.mac));
  add (Printf.sprintf ",\"payload_bytes\":%d" cfg.payload);
  add
    (Printf.sprintf ",\"payload_mode\":\"%s\"" (Payload.payload_mode_name cfg.payload_mode));
  add (Printf.sprintf ",\"seed\":%Lu" cfg.seed);
  add (Printf.sprintf ",\"key_bits\":%d" cfg.key_bits);
  add (Printf.sprintf ",\"nonce_bits\":%d" cfg.nonce_bits);
  add (Printf.sprintf ",\"blob_mode\":%d" cfg.blob_mode);
  add (Printf.sprintf ",\"drbg\":%s" (json_string cfg.drbg));
  add
    (Printf.sprintf ",\"drbg_auto_tier\":%s"
       (json_string (try Itb3.drbg_auto_tier () with Itb3.ITB_error _ -> "")));
  add (Printf.sprintf ",\"chunk_size_bytes\":%d" cfg.chunk_size);
  add (Printf.sprintf ",\"barrier_fill\":%d" cfg.barrier_fill);
  add (Printf.sprintf ",\"parallax\":\"%s\"" (on_off cfg.parallax));
  add (Printf.sprintf ",\"wrapper\":\"%s\"" (on_off cfg.wrapper));
  add (Printf.sprintf ",\"goroutines_requested\":%d" cfg.workers_requested);
  add (Printf.sprintf ",\"goroutines\":%d" cfg.workers);
  add (Printf.sprintf ",\"concurrency\":\"%s\"" concurrency);
  add (Printf.sprintf ",\"gogc\":\"%d\"" (effective_gogc cfg.gogc));
  add (Printf.sprintf ",\"memlimit_bytes\":%Ld" cfg.memlimit);
  add (Printf.sprintf ",\"gomaxprocs\":%d" gomaxprocs);
  add
    (Printf.sprintf ",\"microbatch_tiers\":%s"
       (json_string (policy_label "ITB_MICROBATCH_TIERS")));
  add
    (Printf.sprintf ",\"hashpool_starters\":%s"
       (json_string (policy_label "ITB_HASHPOOL_STARTERS")));
  add (Printf.sprintf ",\"rss_warmup_bytes\":%d" r.rss_warmup);
  add (Printf.sprintf ",\"rss_peak_bytes\":%d" r.rss_peak);
  add (Printf.sprintf ",\"rss_final_bytes\":%d" r.rss_final);
  add (Printf.sprintf ",\"rss_growth_percent\":%.2f" rss_growth);
  let tiers = ref [] in
  for i = pd.tiers - 1 downto 0 do
    if pd.starter.(i) <> 0 then
      tiers :=
        Printf.sprintf
          "{\"tier\":%d,\"starter\":%d,\"get\":%d,\"new\":%d,\"regrow\":%d,\"new_bytes\":%d,\"miss_percent\":%.2f}"
          i pd.starter.(i) pd.get.(i) pd.fresh.(i) pd.regrow.(i) pd.new_bytes.(i)
          (miss_percent (pd.fresh.(i) + pd.regrow.(i)) pd.get.(i))
        :: !tiers
  done;
  add (Printf.sprintf ",\"hash_pool_tiers\":[%s]" (String.concat "," !tiers));
  let pool_json label p =
    Printf.sprintf
      ",\"%s\":{\"get\":%d,\"new\":%d,\"regrow\":%d,\"regrow_bytes\":%d,\"miss_percent\":%.2f}"
      label p.(0) p.(1) p.(2) p.(3) (miss_percent p.(2) p.(0))
  in
  add (pool_json "buf_pool" pd.buf_pool);
  add (pool_json "parallax_chunk_pool" pd.chunk_pool);
  add "}\n";
  write_all Unix.stdout (Buffer.contents out)

(* Output contract. Both renderings are shared with the Go harness and
   every other binding's loop utility field for field: the same lines
   in the same order, the same keys in the same order, floats with a
   fixed number of decimals so the JSON is byte-identical across
   implementations. The Go harness alone adds its runtime-internal
   lines after rss: and its runtime-internal keys after
   parallax_chunk_pool; nothing here reproduces them because nothing
   they read is reachable through the C ABI. *)
let final_summary r elapsed_ns =
  let cfg = r.cfg in
  let sum f = Array.fold_left (fun acc w -> acc + f w) 0 r.workers in
  let total_iters = sum (fun w -> w.iters) in
  let total_enc = sum (fun w -> w.bytes_enc) in
  let total_dec = sum (fun w -> w.bytes_dec) in
  let nanos_enc = sum (fun w -> w.nanos_enc) in
  let nanos_dec = sum (fun w -> w.nanos_dec) in
  let errors =
    Array.to_list r.workers |> List.filter (fun w -> w.failed) |> List.map (fun w -> w.error)
  in

  (* Throughput. Per-direction throughput divides the sum of every
     worker's wall time in that direction by the worker count -- the
     equivalent single-stream wall time under N-way concurrency -- so
     each direction reports the aggregate rate it sustained rather than
     collapsing to combined/2 (every iteration moves equal encrypt and
     decrypt bytes, so a total-elapsed denominator would give both
     directions the same figure). The combined rate keeps total elapsed
     as the one-glance overall figure. *)
  let avg_enc = if nanos_enc > 0 then nanos_enc / cfg.workers else 0 in
  let avg_dec = if nanos_dec > 0 then nanos_dec / cfg.workers else 0 in

  let rss_delta = r.rss_final - r.rss_warmup in
  let rss_growth =
    if r.rss_warmup > 0 then
      100.0 *. float_of_int rss_delta /. float_of_int r.rss_warmup
    else 0.0
  in
  let pd = pool_diff r.pool_warmup r.pool_steady in
  let passed = errors = [] in
  let gomaxprocs = Itb3.set_gomaxprocs 0 in
  let stream_profile = if r.stream_pipe <> None then r.stream_profile else "" in
  let msg_profile = if r.msg_pipe <> None then r.msg_profile else "" in

  if cfg.json_output then begin
    emit_json r elapsed_ns total_iters total_enc total_dec avg_enc avg_dec errors passed
      pd rss_growth gomaxprocs stream_profile msg_profile;
    if passed then 0 else 1
  end
  else begin
    log_line "=== FINAL ===";
    log_line
      ("  duration: "
      ^ Size.human_duration ((elapsed_ns + 500_000) / 1_000_000 * 1_000_000));
    log_line
      (Printf.sprintf "  iterations: %s = %d total"
         (String.concat " + "
            (Array.to_list (Array.map (fun w -> string_of_int w.iters) r.workers)))
         total_iters);
    log_line
      (Printf.sprintf "  throughput: encrypt %s, decrypt %s, combined %s"
         (Size.human_rate total_enc avg_enc)
         (Size.human_rate total_dec avg_dec)
         (Size.human_rate (total_enc + total_dec) elapsed_ns));
    log_line
      (Printf.sprintf "  bytes: %s encrypted, %s decrypted" (Size.human_bytes total_enc)
         (Size.human_bytes total_dec));
    log_line (Printf.sprintf "  data integrity: %d/%d PASS" total_iters total_iters);
    log_line
      (Printf.sprintf "  concurrency: %s, workers %d (requested %d)" concurrency
         cfg.workers cfg.workers_requested);
    log_line
      (Printf.sprintf "  rss: warmup %s, peak %s, final %s (delta %s, %.1f%% growth)"
         (Size.human_bytes r.rss_warmup) (Size.human_bytes r.rss_peak)
         (Size.human_bytes r.rss_final)
         (Size.human_bytes_signed rss_delta) rss_growth);
    for i = 0 to pd.tiers - 1 do
      if pd.starter.(i) <> 0 then begin
        let miss = pd.fresh.(i) + pd.regrow.(i) in
        log_line
          (Printf.sprintf
             "  hash pool tier %d (starter %d): get %d, miss %d (new %d + regrow %d), \
              miss %.2f%%, %s allocated"
             i pd.starter.(i) pd.get.(i) miss pd.fresh.(i) pd.regrow.(i)
             (miss_percent miss pd.get.(i))
             (Size.human_bytes pd.new_bytes.(i)))
      end
    done;
    log_line
      (Printf.sprintf
         "  buf pool: get %d, regrow %d (of which fresh %d), miss %.2f%%, %s regrown"
         pd.buf_pool.(0) pd.buf_pool.(2) pd.buf_pool.(1)
         (miss_percent pd.buf_pool.(2) pd.buf_pool.(0))
         (Size.human_bytes pd.buf_pool.(3)));
    log_line
      (Printf.sprintf
         "  parallax chunk pool: get %d, regrow %d (of which fresh %d), miss %.2f%%, %s \
          regrown"
         pd.chunk_pool.(0) pd.chunk_pool.(2) pd.chunk_pool.(1)
         (miss_percent pd.chunk_pool.(2) pd.chunk_pool.(0))
         (Size.human_bytes pd.chunk_pool.(3)));
    if r.rekeys > 0 then log_line (Printf.sprintf "  rekeys: %d" r.rekeys);
    if r.blob_cycles > 0 then log_line (Printf.sprintf "  blob cycles: %d" r.blob_cycles);
    List.iter (fun text -> log_line ("  ERROR: " ^ text)) errors;
    if passed then begin
      log_line "  verdict: PASS";
      0
    end
    else begin
      log_line (Printf.sprintf "  verdict: FAIL (errors=%d)" (List.length errors));
      1
    end
  end
