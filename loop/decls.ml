(* Shared declarations of the loop stress harness: the resolved
   configuration, the per-worker state, the run state, the growable
   output buffer the pump loop accumulates into, and the output helpers
   every unit logs through.

   OCaml-specific. A module may not refer to one compiled after it, so
   two units that each name a type the other defines cannot both come
   first; the worker unit drives maintenance and the ops unit reads the
   run state, which is exactly that shape. A declarations unit holding
   what both sides need is the same answer the C reference reaches with
   its header. *)

(* Cipher surfaces the --shape flag selects. *)
type shape =
  | Stream (* session pump: begin / write / read / end *)
  | Message (* Single Message: one whole-buffer call *)
  | Stream_one_shot (* stream surface, one whole-buffer call *)
  | Both (* all three, rotating by iteration number *)

(* Plaintext content policies the --payload-mode flag selects. *)
type payload_mode =
  | Fixed
  | Rotating
  | Pattern_zero
  | Pattern_ff
  | Pattern_ascii

(* --goroutines ceiling; the harness targets modest hosts and each
   worker pins payload-sized buffers for the whole run. *)
let max_workers = 10

(* The concurrency mode this binding implements, as the summary reports
   it (shared-handle / independent-handles / single). *)
let concurrency = "single"

(* Largest slice fed to a stream session per write; the drain after
   every write uses the same bound. *)
let pump_slice = 1 lsl 20

(* The resolved command line. *)
type config = {
  mutable duration_ns : int; (* run duration; ignored when iterations > 0 *)
  mutable iterations : int; (* per-worker count incl. warmup; 0 = duration-based *)
  mutable workers_requested : int; (* the --goroutines value as given *)
  mutable workers : int; (* the effective worker count *)
  mutable shape : shape;
  mutable hash : string;
  mutable mac : string;
  mutable payload : int; (* bytes per iteration *)
  mutable memlimit : int64; (* resolved bytes; the effective limit once shaped *)
  mutable memlimit_auto : bool; (* --memlimit auto: cap only when the runtime has none *)
  mutable gogc : int; (* 0 = leave the runtime default *)
  mutable parallax : bool;
  mutable wrapper : bool;
  mutable profile : string; (* empty = shape-based profile pair *)
  mutable key_bits : int; (* 0 = profile default *)
  mutable nonce_bits : int; (* 0 = profile default *)
  mutable blob_mode : int; (* container floor sizing mode: 1 (per-region, default) | 2 (per-container) *)
  mutable chunk_size : int; (* 0 = profile default *)
  mutable barrier_fill : int; (* 0 = profile default *)
  mutable drbg : string; (* DRBG fill primitive; "" = profile default (auto tier) *)
  mutable gomaxprocs : int; (* 0 = inherit from the environment *)
  mutable rekey_every : int; (* per-worker iterations between rotations; 0 = never *)
  mutable blob_cycle_every : int; (* per-worker iterations between reopens; 0 = never *)
  mutable payload_mode : payload_mode;
  mutable seed : int64; (* 0 = OS CSPRNG plaintexts *)
  mutable json_output : bool;
  mutable memprofile : string; (* empty = none *)
}

let default_config () =
  {
    duration_ns = 0;
    iterations = 0;
    workers_requested = 0;
    workers = 0;
    shape = Stream;
    hash = "";
    mac = "";
    payload = 0;
    memlimit = 0L;
    memlimit_auto = false;
    gogc = 0;
    parallax = true;
    wrapper = true;
    profile = "";
    key_bits = 0;
    nonce_bits = 0;
    blob_mode = 1;
    chunk_size = 0;
    barrier_fill = 0;
    drbg = "";
    gomaxprocs = 0;
    rekey_every = 0;
    blob_cycle_every = 0;
    payload_mode = Fixed;
    seed = 0L;
    json_output = false;
    memprofile = "";
  }

(* OCaml-specific. A grow-only byte accumulator reused across
   iterations, so the steady-state allocation profile of the pump loop
   stays flat; the standard [Buffer] would do the same job but hands
   its contents back as a fresh copy on every read, which at payload
   scale is one extra copy of the whole wire per direction per
   iteration. *)
type buf = { mutable data : Bytes.t; mutable len : int }

let buf_create () = { data = Bytes.create 0; len = 0 }
let buf_reset b = b.len <- 0

let buf_append b src n =
  if n > 0 then begin
    if b.len + n > Bytes.length b.data then begin
      let cap = ref (max (Bytes.length b.data) pump_slice) in
      while !cap < b.len + n do
        cap := !cap * 2
      done;
      let grown = Bytes.create !cap in
      Bytes.blit b.data 0 grown 0 b.len;
      b.data <- grown
    end;
    Bytes.blit src 0 b.data b.len n;
    b.len <- b.len + n
  end

(* One worker's private state: its plaintext, its reusable output
   buffers, its generator, its counters, and the error it stopped on. *)
type worker = {
  id : int;
  mutable plaintext : Bytes.t;
  mutable payload_mode : payload_mode;
  mutable seeded : bool;
  mutable rng : int64; (* splitmix64 state when seeded *)
  wire : buf; (* pump-loop wire accumulator *)
  plain : buf; (* pump-loop round-trip accumulator *)
  scratch : Bytes.t; (* pump-loop drain slice *)
  (* Counters read by the summary once the worker has returned. *)
  mutable iters : int;
  mutable bytes_enc : int;
  mutable bytes_dec : int;
  mutable nanos_enc : int;
  mutable nanos_dec : int;
  mutable failed : bool;
  mutable error : string;
}

let make_worker id =
  {
    id;
    plaintext = Bytes.create 0;
    payload_mode = Fixed;
    seeded = false;
    rng = 0L;
    wire = buf_create ();
    plain = buf_create ();
    scratch = Bytes.create pump_slice;
    iters = 0;
    bytes_enc = 0;
    bytes_dec = 0;
    nanos_enc = 0;
    nanos_dec = 0;
    failed = false;
    error = "";
  }

(* The run state: the Pipeline handles, the retained blobs, the stop
   request, the workers, and the baselines the summary reads. *)
type run_state = {
  cfg : config;
  mutable stream_pipe : Itb3.pipeline option; (* None unless the shape uses it *)
  mutable msg_pipe : Itb3.pipeline option; (* None unless the shape uses it *)
  mutable stream_profile : string;
  mutable msg_profile : string;
  (* The blob Init handed out, replaced by every rekey; the input of
     the next blob reopen. *)
  mutable stream_blob : Bytes.t;
  mutable msg_blob : Bytes.t;
  mutable rekeys : int;
  mutable blob_cycles : int;
  mutable workers : worker array;
  (* Set by the duration deadline, by a signal, or by a failing
     worker; checked before every iteration. *)
  mutable stop : bool;
  mutable start_ns : int;
  mutable finish_ns : int;
  (* Baselines taken after the warmup iteration and at shutdown. *)
  mutable rss_warmup : int;
  mutable rss_peak : int;
  mutable rss_final : int;
  mutable pool_warmup : int array;
  mutable pool_steady : int array;
}

let make_run_state cfg =
  {
    cfg;
    stream_pipe = None;
    msg_pipe = None;
    stream_profile = "";
    msg_profile = "";
    stream_blob = Bytes.create 0;
    msg_blob = Bytes.create 0;
    rekeys = 0;
    blob_cycles = 0;
    workers = [||];
    stop = false;
    start_ns = 0;
    finish_ns = 0;
    rss_warmup = 0;
    rss_peak = 0;
    rss_final = 0;
    pool_warmup = [||];
    pool_steady = [||];
  }

(* OCaml-specific. Both emitters go to the descriptor rather than
   through a buffered channel, which gives the whole terminated line to
   one write call: the property the contract asks for does not then
   depend on how large a channel buffer happens to be or on when a
   flush lands relative to anything else writing. *)
let write_all fd text =
  let len = String.length text in
  let rec loop off =
    if off < len then
      match Unix.write_substring fd text off (len - off) with
      | 0 -> ()
      | n -> loop (off + n)
  in
  try loop 0 with Unix.Unix_error _ -> ()

(* Prints one prefixed status line to stdout. *)
let log_line text = write_all Unix.stdout ("[loop] " ^ text ^ "\n")

(* Prints one prefixed diagnostic to stderr. *)
let err_line text = write_all Unix.stderr ("loop: " ^ text ^ "\n")

let on_off b = if b then "on" else "off"

(* Renders an encoder policy env value for the summary: the raw string
   when set, "default" when the shipped ladder applies. *)
let policy_label name =
  match Sys.getenv_opt name with
  | None -> "default"
  | Some raw ->
      let n = String.length raw in
      let i = ref 0 in
      while !i < n && (raw.[!i] = ' ' || raw.[!i] = '\t') do
        incr i
      done;
      if !i >= n then "default" else String.sub raw !i (n - !i)

(* The failure detail a log line carries: the numeric status the
   binding's own surface exposes and the finished sentence the library
   left behind. Nothing is composed here -- the wording arrives whole
   from the failing call. *)
let status_detail = function
  | Itb3.ITB_error (code, message) -> Printf.sprintf "status %d: %s" code message
  | exn -> Printexc.to_string exn

(* Records the worker's error text (first error wins) and requests a
   stop of the whole run. *)
let worker_fail r w text =
  if not w.failed then begin
    w.error <- text;
    w.failed <- true
  end;
  r.stop <- true
