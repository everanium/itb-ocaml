(* Plaintext content: the payload modes, the seeded per-worker
   generator, and the buffer fill from the operating-system CSPRNG. *)

open Decls

(* Payload mode selector values for the --payload-mode flag.

     - fixed: one CSPRNG-generated buffer per worker, held unchanged
       for the whole run (the default).
     - rotating: the buffer is regenerated before every iteration, so
       no two encrypt calls see the same plaintext.
     - pattern-zero / pattern-ff: degenerate constant fills (all 0x00 /
       all 0xFF) probing minimum-entropy plaintext handling.
     - pattern-ascii: a repeating 'A'..'Z' ramp probing low-entropy
       structured text. *)
let payload_names =
  [ (Fixed, "fixed"); (Rotating, "rotating"); (Pattern_zero, "pattern-zero");
    (Pattern_ff, "pattern-ff"); (Pattern_ascii, "pattern-ascii") ]

let payload_mode_name mode = List.assoc mode payload_names

let parse_payload_mode s =
  match List.find_opt (fun (_, name) -> name = s) payload_names with
  | Some (mode, _) -> Some mode
  | None -> None

(* Seeded plaintext. The seed makes plaintext content reproducible so a
   failing iteration can be replayed with the same bytes; it governs
   nothing else -- pipeline keys, nonces and masters stay CSPRNG-drawn,
   so a seeded run is a reproduction aid and never a security test.
   Each worker's stream is domain-separated by its id so seeded workers
   still hold pairwise-distinct buffers under the fixed and rotating
   modes. The generator is splitmix64: a few lines in any language,
   which is why it is the one every binding uses. *)
let seed_worker seed worker_id = Int64.add seed (Int64.of_int (worker_id + 1))

(* One splitmix64 draw; returns the advanced state and the output. *)
let splitmix64 state =
  let state = Int64.add state 0x9E3779B97F4A7C15L in
  let z = state in
  let z =
    Int64.mul (Int64.logxor z (Int64.shift_right_logical z 30)) 0xBF58476D1CE4E5B9L
  in
  let z =
    Int64.mul (Int64.logxor z (Int64.shift_right_logical z 27)) 0x94D049BB133111EBL
  in
  (state, Int64.logxor z (Int64.shift_right_logical z 31))

(* Fills the first [n] bytes of [dst] from the operating-system
   CSPRNG. Returns false when the draw failed.

   OCaml-specific. The standard library offers no entropy entry of its
   own, so the draw reads /dev/urandom through the unbuffered
   descriptor calls: a buffered channel would pull a block of
   read-ahead the caller never asked for, and the loop here is bounded
   by the caller's own buffer rather than by any internal per-call
   ceiling. *)
let fill_random dst n =
  if n <= 0 then true
  else
    match Unix.openfile "/dev/urandom" [ Unix.O_RDONLY; Unix.O_CLOEXEC ] 0 with
    | exception Unix.Unix_error _ -> false
    | fd ->
        let ok = ref true in
        let off = ref 0 in
        (try
           while !ok && !off < n do
             let got = Unix.read fd dst !off (n - !off) in
             if got <= 0 then ok := false else off := !off + got
           done
         with Unix.Unix_error _ -> ok := false);
        Unix.close fd;
        !ok

(* Writes one plaintext buffer according to the payload mode and
   returns the advanced generator state, or None when the CSPRNG
   failed. The fixed and rotating modes draw from the seeded generator
   when the run is seeded and from the OS CSPRNG otherwise; the pattern
   modes are deterministic regardless of the seed. *)
let fill_payload dst mode seeded rng =
  let n = Bytes.length dst in
  match mode with
  | Fixed | Rotating ->
      if not seeded then if fill_random dst n then Some rng else None
      else begin
        let state = ref rng in
        let i = ref 0 in
        while !i < n do
          let advanced, value = splitmix64 !state in
          state := advanced;
          let take = min (n - !i) 8 in
          for k = 0 to take - 1 do
            Bytes.set dst (!i + k)
              (Char.chr
                 (Int64.to_int
                    (Int64.logand (Int64.shift_right_logical value (8 * k)) 0xFFL)))
          done;
          i := !i + take
        done;
        Some !state
      end
  | Pattern_zero ->
      Bytes.fill dst 0 n '\000';
      Some rng
  | Pattern_ff ->
      Bytes.fill dst 0 n '\255';
      Some rng
  | Pattern_ascii ->
      for i = 0 to n - 1 do
        Bytes.set dst i (Char.chr (0x41 + (i mod 26)))
      done;
      Some rng
