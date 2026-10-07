(* The maintenance operations that mutate a live Pipeline handle
   between iterations: master rotation (--rekey-every) and blob reopen
   (--blob-cycle-every). *)

open Decls

(* Byte length of each fresh master drawn for a rotation. Matches the
   size Init auto-generates for both the parallax and the wrapper
   master. *)
let rekey_master_size = 32

(* Master rotation. Rotates the parallax + wrapper masters on every
   active Pipeline and retains the refreshed blob for subsequent blob
   reopens. Masters are drawn fresh from the OS CSPRNG on every
   rotation regardless of --seed (master rotation is pipeline keying,
   not plaintext content); a disabled layer passes no bytes, which
   Rekey ignores. The eight inner seeds and the MAC key are untouched
   by design -- Rekey targets only the two outer-layer master
   secrets. *)
let rekey_pipes r w iter =
  let perm = Bytes.create (if r.cfg.parallax then rekey_master_size else 0) in
  let wrap = Bytes.create (if r.cfg.wrapper then rekey_master_size else 0) in
  if not (Payload.fill_random perm (Bytes.length perm)) then begin
    worker_fail r w (Printf.sprintf "g%d iter %d: csprng: parallax master" w.id iter);
    false
  end
  else if not (Payload.fill_random wrap (Bytes.length wrap)) then begin
    worker_fail r w (Printf.sprintf "g%d iter %d: csprng: wrapper master" w.id iter);
    false
  end
  else begin
    let ok = ref true in
    let rekey_one pipe profile =
      if !ok then
        match pipe with
        | None -> None
        | Some handle -> (
            match Itb3.rekey ~perm ~wrap handle with
            | blob -> Some blob
            | exception exn ->
                worker_fail r w
                  (Printf.sprintf "g%d iter %d: Rekey(%s): %s" w.id iter profile
                     (status_detail exn));
                ok := false;
                None)
      else None
    in
    (match rekey_one r.stream_pipe r.stream_profile with
    | Some blob -> r.stream_blob <- blob
    | None -> ());
    (match rekey_one r.msg_pipe r.msg_profile with
    | Some blob -> r.msg_blob <- blob
    | None -> ());
    if !ok then begin
      r.rekeys <- r.rekeys + 1;
      log_line
        (Printf.sprintf
           "rekey: g%d iter %d rotated parallax + wrapper masters (rekey #%d)" w.id iter
           r.rekeys)
    end;
    !ok
  end

(* Blob reopen. Reopens every active Pipeline from its retained blob: a
   fresh handle is loaded from the blob, the running handle is
   released, and the fresh one is swapped in, so every later iteration
   round-trips through seeds and masters that survived a blob crossing.
   The input is the blob Init or the latest Rekey handed out, not a
   fresh Save: that is what a receiver holds, and reopening from it
   proves the handed-out bytes rather than the live state. The blob
   carries the Pipeline's full shape, so no override reaches the
   reopen. On a Load failure the running handle stays and the failure
   aborts the run.

   OCaml-specific. The retired handle is closed rather than freed: the
   binding's surface has no free, and close is what zeroes the key
   material of a handle the utility is done with on the spot. The
   handle slot itself goes back to the library when the collector runs
   the value's finaliser. *)
let blob_cycle_pipes r w iter =
  let ok = ref true in
  let reopen pipe profile blob =
    if !ok then
      match pipe with
      | None -> None
      | Some handle -> (
          match Itb3.load blob with
          | fresh ->
              (try Itb3.close handle with Itb3.ITB_error _ -> ());
              Some fresh
          | exception exn ->
              worker_fail r w
                (Printf.sprintf "g%d iter %d: Load(%s): %s" w.id iter profile
                   (status_detail exn));
              ok := false;
              None)
    else None
  in
  (match reopen r.stream_pipe r.stream_profile r.stream_blob with
  | Some fresh -> r.stream_pipe <- Some fresh
  | None -> ());
  (match reopen r.msg_pipe r.msg_profile r.msg_blob with
  | Some fresh -> r.msg_pipe <- Some fresh
  | None -> ());
  if !ok then begin
    r.blob_cycles <- r.blob_cycles + 1;
    log_line
      (Printf.sprintf "blob-cycle: g%d iter %d reopened from session blob (cycle #%d)"
         w.id iter r.blob_cycles)
  end;
  !ok

(* Handle mutation. Runs the periodic Pipeline-mutating operations
   after a completed iteration: master rotation (--rekey-every) and
   blob reopen (--blob-cycle-every). Both intervals count per-worker
   iterations; the warmup iteration (iter 0) never triggers because the
   worker loop calls this for iter >= 1 only. Rekey rewrites the
   outer-layer keying of a live handle and a blob reopen replaces the
   handle outright. Neither takes a lock here: this binding runs the
   single mode, so the one worker is between iterations whenever this
   runs and there is no second caller a lock could be keeping clear of
   the handle. Returns false after recording a worker error. *)
let worker_maintenance r w iter =
  let cfg = r.cfg in
  if cfg.rekey_every > 0 && iter mod cfg.rekey_every = 0 && not (rekey_pipes r w iter)
  then false
  else if
    cfg.blob_cycle_every > 0
    && iter mod cfg.blob_cycle_every = 0
    && not (blob_cycle_pipes r w iter)
  then false
  else true
