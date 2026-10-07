(* Size and duration parsing, the monotonic clock, and the human
   renderings of sizes, rates and durations. Every rendering here is
   part of the output contract shared with the Go harness and the other
   bindings' loop utilities, so the formats are fixed to the character,
   not to taste. *)

(* Byte-size suffixes, longest first so "KIB" is matched before "K"
   and "B" never swallows the tail of another suffix. Every multiple is
   binary. *)
let size_suffixes =
  [
    ("KIB", 1024);
    ("KB", 1024);
    ("K", 1024);
    ("MIB", 1024 * 1024);
    ("MB", 1024 * 1024);
    ("M", 1024 * 1024);
    ("GIB", 1024 * 1024 * 1024);
    ("GB", 1024 * 1024 * 1024);
    ("G", 1024 * 1024 * 1024);
    ("B", 1);
  ]

(* Duration units in the order the grammar probes them, so "ms" is
   taken before "m" and "s". *)
let duration_units =
  [ ("ns", 1.0); ("us", 1e3); ("ms", 1e6); ("s", 1e9); ("m", 60e9); ("h", 3600e9) ]

let is_space c = c = ' ' || c = '\t' || c = '\n' || c = '\r'
let is_digit c = c >= '0' && c <= '9'
let is_letter c = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')

let starts_with_at s pos prefix =
  let n = String.length prefix in
  pos + n <= String.length s && String.sub s pos n = prefix

(* Parses a human byte-size string ("16MB", "1MiB", "512K",
   "1073741824") into a byte count. Every suffix is a binary multiple:
   K/KB/KiB = 1024, M/MB/MiB = 1024^2, G/GB/GiB = 1024^3, B or none =
   bytes; matching is case-insensitive and surrounding whitespace is
   trimmed. Returns None on a malformed or negative value. *)
let parse_size s =
  let upper = String.uppercase_ascii (String.trim s) in
  if String.length upper = 0 then None
  else begin
    let mult, digits =
      match
        List.find_opt
          (fun (suffix, _) ->
            let n = String.length suffix in
            String.length upper >= n
            && String.sub upper (String.length upper - n) n = suffix)
          size_suffixes
      with
      | Some (suffix, m) ->
          (m, String.sub upper 0 (String.length upper - String.length suffix))
      | None -> (1, upper)
    in
    let digits =
      let n = ref (String.length digits) in
      while !n > 0 && is_space digits.[!n - 1] do
        decr n
      done;
      String.sub digits 0 !n
    in
    if String.length digits = 0 then None
    else if not (String.for_all is_digit digits) then None
    else
      match Int64.of_string_opt digits with
      | None -> None
      | Some n ->
          if mult > 1 && n > Int64.div Int64.max_int (Int64.of_int mult) then None
          else
            let scaled = Int64.mul n (Int64.of_int mult) in
            if scaled > Int64.of_int max_int then None else Some (Int64.to_int scaled)
  end

(* Parses the Go duration grammar -- a sequence of decimal numbers each
   followed by a unit (h, m, s, ms, us, ns), such as "30s", "5m",
   "1h30m", "1.5s" -- into nanoseconds. Returns None on a malformed
   string. *)
let parse_duration s =
  let n = String.length s in
  if n = 0 then None
  else begin
    let total = ref 0.0 in
    let pos = ref 0 in
    let bad = ref false in
    while (not !bad) && !pos < n do
      let start = !pos in
      while !pos < n && (is_digit s.[!pos] || s.[!pos] = '.') do
        incr pos
      done;
      if !pos = start then bad := true
      else
        match float_of_string_opt (String.sub s start (!pos - start)) with
        | None -> bad := true
        | Some value when value < 0.0 -> bad := true
        | Some value -> (
            match
              List.find_opt
                (fun (unit, _) ->
                  starts_with_at s !pos unit
                  &&
                  let after = !pos + String.length unit in
                  not (after < n && is_letter s.[after]))
                duration_units
            with
            | None -> bad := true
            | Some (unit, ns) ->
                pos := !pos + String.length unit;
                total := !total +. (value *. ns))
    done;
    if !bad || !total > 9.2e18 then None else Some (int_of_float !total)
  end

(* Monotonic wall clock in nanoseconds. *)
let now_ns () = int_of_float (Unix.gettimeofday () *. 1e9)

(* Renders a byte count with a binary-unit suffix: "1.0GiB", "16.0MiB",
   "4.0KiB", "512B". *)
let human_bytes n =
  if n >= 1024 * 1024 * 1024 then
    Printf.sprintf "%.1fGiB" (float_of_int n /. float_of_int (1024 * 1024 * 1024))
  else if n >= 1024 * 1024 then
    Printf.sprintf "%.1fMiB" (float_of_int n /. float_of_int (1024 * 1024))
  else if n >= 1024 then Printf.sprintf "%.1fKiB" (float_of_int n /. 1024.0)
  else Printf.sprintf "%dB" n

(* Renders a possibly-negative byte delta with an explicit sign. *)
let human_bytes_signed n =
  if n < 0 then "-" ^ human_bytes (-n) else "+" ^ human_bytes n

(* Binary MiB per second over a nanosecond window; 0 when the window is
   unmeasured. *)
let mb_per_sec bytes ns =
  if ns <= 0 then 0.0
  else float_of_int bytes /. float_of_int (1024 * 1024) /. (float_of_int ns /. 1e9)

(* Renders a throughput as "123.4MB/s" (binary MiB per second) or "n/a"
   for an unmeasured window. *)
let human_rate bytes ns =
  if ns <= 0 then "n/a" else Printf.sprintf "%.1fMB/s" (mb_per_sec bytes ns)

(* The fractional part of a nanosecond remainder (0 .. 1e9) as ".ddd"
   with trailing zeros removed; empty for zero. *)
let fraction frac_ns =
  if frac_ns = 0 then ""
  else begin
    let digits = Printf.sprintf "%09d" frac_ns in
    let n = ref (String.length digits) in
    while !n > 0 && digits.[!n - 1] = '0' do
      decr n
    done;
    "." ^ String.sub digits 0 !n
  end

(* Renders a duration the way Go's time.Duration prints: below one
   second as milliseconds ("900ms", "1.5ms"); otherwise "[Hh][Mm]Ss"
   where the hour part appears when non-zero, the minute part when the
   hour part appears or the minutes are non-zero, and the seconds carry
   their fraction with trailing zeros removed ("5s", "5.003s", "1m0s",
   "1m5.25s", "1h0m0s"). The caller rounds first. *)
let human_duration ns =
  let ns = abs ns in
  if ns = 0 then "0s"
  else if ns < 1_000_000_000 then
    (* Scale the sub-millisecond remainder to nine digits so the
       fraction renderer sees the same shape it does for seconds. *)
    Printf.sprintf "%d%sms" (ns / 1_000_000) (fraction (ns mod 1_000_000 * 1000))
  else begin
    let hours = ns / 3_600_000_000_000 in
    let rest = ns mod 3_600_000_000_000 in
    let minutes = rest / 60_000_000_000 in
    let rest = rest mod 60_000_000_000 in
    let seconds = rest / 1_000_000_000 in
    let frac = rest mod 1_000_000_000 in
    let head = if hours > 0 then Printf.sprintf "%dh" hours else "" in
    let head =
      if hours > 0 || minutes > 0 then head ^ Printf.sprintf "%dm" minutes else head
    in
    Printf.sprintf "%s%d%ss" head seconds (fraction frac)
  end
