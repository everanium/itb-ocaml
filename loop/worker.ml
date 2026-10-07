(* The worker: its body (the warmup iteration, then the main loop), one
   iteration, the session pump loop the stream shape drives, and the
   round-trip comparison that decides between a worker error and a data
   mismatch. *)

open Decls

let shape_names =
  [ (Stream, "stream"); (Message, "message"); (Stream_one_shot, "stream_one_shot");
    (Both, "both") ]

let shape_name shape = List.assoc shape shape_names

let parse_shape s =
  match List.find_opt (fun (_, name) -> name = s) shape_names with
  | Some (shape, _) -> Some shape
  | None -> None

(* Pump loop. The Go harness hands ITB an io.Reader / io.Writer pair
   and ITB drives the chunk loop internally; the C ABI has no reader /
   writer entry, so the caller drives it: open a session, feed slices
   of at most 1 MiB, drain whatever the session has produced after
   every write (a read before end never blocks), end, then drain until
   the session reports finished (after end, a read on an empty spool
   blocks until the terminal bytes arrive). The whole produced output
   lands in the worker's reusable accumulator. The loop is written here
   rather than delegated to the binding's pump convenience so it stands
   in the utility, at the same place, in every language.

   The drain that reports finished is also what releases the session on
   this binding's surface, so a run that completes the loop leaves
   nothing behind; one that raises part way through leaves the session
   to the finaliser the binding attached to it. *)
let drive sess src src_len out scratch =
  buf_reset out;
  let cap = Bytes.length scratch in
  let off = ref 0 in
  while !off < src_len do
    let slice = min pump_slice (src_len - !off) in
    Itb3.write_sub sess src !off slice;
    off := !off + slice;
    let draining = ref true in
    while !draining do
      let n, _ = Itb3.read_into sess scratch cap in
      if n = 0 then draining := false else buf_append out scratch n
    done
  done;
  Itb3.end_ sess;
  let finished = ref false in
  while not !finished do
    let n, fin = Itb3.read_into sess scratch cap in
    if n > 0 then buf_append out scratch n;
    finished := fin
  done

let pump_encrypt pipe src src_len out scratch =
  drive (Itb3.encrypt_stream pipe) src src_len out scratch

let pump_decrypt pipe src src_len out scratch =
  drive (Itb3.decrypt_stream pipe) src src_len out scratch

(* First offset at which the two buffers differ; the shorter length
   when one is a prefix of the other. *)
let first_difference a alen b blen =
  let n = min alen blen in
  let i = ref 0 in
  while !i < n && Bytes.get a !i = Bytes.get b !i do
    incr i
  done;
  !i

(* Up to 16 bytes of [buf] from [off] as lowercase hex, or "-" when
   [buf] has no bytes there. *)
let hex_window buf len off =
  if off >= len then "-"
  else begin
    let last = min (off + 16) len in
    let out = Buffer.create 32 in
    for i = off to last - 1 do
      Buffer.add_string out (Printf.sprintf "%02x" (Char.code (Bytes.get buf i)))
    done;
    Buffer.contents out
  end

(* Records a worker error for a failed cipher call. *)
let cipher_fail r w iter shape direction exn =
  worker_fail r w
    (Printf.sprintf "g%d iter %d shape=%s: %s: %s" w.id iter (shape_name shape)
       direction (status_detail exn))

(* Shape dispatch. The surface of one iteration. message is one
   whole-buffer call on the Single Message Pipeline;
   stream_one_shot is one whole-buffer call on the streaming Pipeline
   (the C ABI's ITB_Triple_EncryptStream, which routes to the same
   one-shot stream entry the Go harness calls by name); stream
   opens a session on the same streaming Pipeline and drives the chunk
   loop from here. Under both the three rotate by iteration number so
   the session path and the whole-buffer path alternate on one handle
   inside every worker -- the cross-path state-reuse hazard this
   harness exists to catch. *)
let iteration_shape configured iter =
  match configured with
  | Both -> ( match iter mod 3 with 0 -> Stream | 1 -> Message | _ -> Stream_one_shot)
  | shape -> shape

(* One iteration. In order: refill the plaintext under rotating mode;
   pick the surface; encrypt (timed); decrypt (timed); compare the
   round-trip with the plaintext; bump the counters. The read lock the
   contract places around the round-trip has no counterpart here: this
   binding runs the single mode, so no second caller can be inside a
   cipher call while maintenance mutates a handle, and maintenance runs
   from the worker loop after this returns -- never between an encrypt
   and its matching decrypt. Returns false after recording the worker
   error. *)
let iterate r w iter =
  let refill_ok =
    if w.payload_mode <> Rotating then true
    else
      match Payload.fill_payload w.plaintext Rotating w.seeded w.rng with
      | Some advanced ->
          w.rng <- advanced;
          true
      | None ->
          worker_fail r w (Printf.sprintf "g%d iter %d: payload refill: csprng" w.id iter);
          false
  in
  if not refill_ok then false
  else begin
    let shape = iteration_shape r.cfg.shape iter in
    let want = w.plaintext in
    let want_len = Bytes.length want in
    let got = ref want in
    let got_len = ref 0 in
    let ok = ref true in
    (match shape with
    | Stream -> (
        let pipe = Option.get r.stream_pipe in
        let t0 = Size.now_ns () in
        match pump_encrypt pipe want want_len w.wire w.scratch with
        | () -> (
            w.nanos_enc <- w.nanos_enc + (Size.now_ns () - t0);
            let t1 = Size.now_ns () in
            match pump_decrypt pipe w.wire.data w.wire.len w.plain w.scratch with
            | () ->
                w.nanos_dec <- w.nanos_dec + (Size.now_ns () - t1);
                got := w.plain.data;
                got_len := w.plain.len
            | exception exn ->
                cipher_fail r w iter shape "decrypt" exn;
                ok := false)
        | exception exn ->
            cipher_fail r w iter shape "encrypt" exn;
            ok := false)
    | Message | Stream_one_shot -> (
        let pipe =
          Option.get (if shape = Message then r.msg_pipe else r.stream_pipe)
        in
        let encrypt =
          if shape = Message then Itb3.encrypt_message else Itb3.encrypt_stream_one_shot
        in
        let decrypt =
          if shape = Message then Itb3.decrypt_message else Itb3.decrypt_stream_one_shot
        in
        let t0 = Size.now_ns () in
        match encrypt pipe want with
        | wire -> (
            w.nanos_enc <- w.nanos_enc + (Size.now_ns () - t0);
            let t1 = Size.now_ns () in
            match decrypt pipe wire with
            | back ->
                w.nanos_dec <- w.nanos_dec + (Size.now_ns () - t1);
                got := back;
                got_len := Bytes.length back
            | exception exn ->
                cipher_fail r w iter shape "decrypt" exn;
                ok := false)
        | exception exn ->
            cipher_fail r w iter shape "encrypt" exn;
            ok := false)
    | Both -> ());
    if not !ok then false
    else begin
      (* Failure model. A cipher call that returns a non-OK status is a
         worker error: it is recorded, the run is asked to stop, and the
         error is listed in the summary with the FAIL verdict. A
         round-trip that returns OK with different bytes is a data
         mismatch: the process terminates here, without summary or
         cleanup, because the Pipeline state that produced the wrong
         bytes is the evidence and nothing that runs afterwards may
         touch it. *)
      if !got_len <> want_len || first_difference want want_len !got !got_len < want_len
      then begin
        let off = first_difference want want_len !got !got_len in
        err_line
          (Printf.sprintf
             "DATA MISMATCH g%d iter %d shape=%s: want %d bytes, got %d bytes, first \
              difference at offset %d: want %s got %s"
             w.id iter (shape_name shape) want_len !got_len off
             (hex_window want want_len off)
             (hex_window !got !got_len off));
        (* OCaml-specific. _exit leaves the process on the spot without
           running an at_exit action or flushing a channel, which is
           what "no summary, no cleanup" asks for; exit would unwind
           and let the shutdown path run over the evidence. *)
        Unix._exit 3
      end;
      w.iters <- w.iters + 1;
      w.bytes_enc <- w.bytes_enc + want_len;
      w.bytes_dec <- w.bytes_dec + !got_len;
      true
    end
  end

(* The worker's warmup iteration -- counted in the totals; its
   completion feeds the post-warmup baselines. *)
let warmup r w = iterate r w 0

(* The worker's main loop: iterations until a stop is requested, the
   duration deadline passes, or the fixed per-worker iteration budget
   (warmup included) is spent. A stop is checked before every
   iteration, so an in-flight one always completes. *)
let run_worker r w stop_requested =
  let iter = ref 1 in
  let running = ref true in
  while !running do
    if r.cfg.iterations > 0 && !iter >= r.cfg.iterations then running := false
    else if stop_requested () then running := false
    else if r.stop then running := false
    else if
      r.cfg.iterations = 0 && Size.now_ns () - r.start_ns >= r.cfg.duration_ns
    then running := false
    else if not (iterate r w !iter) then running := false
    else if not (Ops.worker_maintenance r w !iter) then running := false
    else incr iter
  done;
  r.finish_ns <- Size.now_ns ()
