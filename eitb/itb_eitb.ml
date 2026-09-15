(* eitb -- command-line demonstrator for the ITB OCaml binding.

   Subcommands:

     eitb version                                   library + binding versions
     eitb profiles                                  registered profile catalogue
     eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
     eitb decrypt <profile> <blob-hex> <in-file> <out-file>

   [encrypt] prints the session blob to stderr as hex; feed that hex
   back to [decrypt] on the receiving side. [profiles] lists the
   registered profile catalogue one name per line; the profiles that
   carry a cipher surface are the ones [encrypt] / [decrypt] accept. *)

let usage =
  "usage: eitb version\n\
  \       eitb profiles\n\
  \       eitb encrypt <profile> <in-file> <out-file>\n\
  \       eitb decrypt <profile> <blob-hex> <in-file> <out-file>"

let read_file path =
  let ic = open_in_bin path in
  Fun.protect
    ~finally:(fun () -> close_in_noerr ic)
    (fun () ->
      let n = in_channel_length ic in
      let buf = Bytes.create n in
      really_input ic buf 0 n;
      buf)

let write_file path data =
  let oc = open_out_bin path in
  Fun.protect
    ~finally:(fun () -> close_out_noerr oc)
    (fun () -> output_bytes oc data)

let to_hex b =
  let out = Buffer.create (2 * Bytes.length b) in
  Bytes.iter (fun c -> Buffer.add_string out (Printf.sprintf "%02x" (Char.code c))) b;
  Buffer.contents out

let of_hex s =
  let n = String.length s in
  if n = 0 || n mod 2 <> 0 then
    raise (Itb3.ITB_error (-1, "blob hex: odd length or empty"));
  let nib c =
    match c with
    | '0' .. '9' -> Char.code c - Char.code '0'
    | 'a' .. 'f' -> Char.code c - Char.code 'a' + 10
    | 'A' .. 'F' -> Char.code c - Char.code 'A' + 10
    | _ -> raise (Itb3.ITB_error (-1, "blob hex: non-hex character"))
  in
  Bytes.init (n / 2) (fun i -> Char.chr ((nib s.[2 * i] lsl 4) lor nib s.[(2 * i) + 1]))

let cmd_version () =
  Printf.printf "libitb3 %s\n" (Itb3.version ());
  Printf.printf "itb-ocaml %s\n" Itb3.binding_version

let cmd_profiles () = List.iter print_endline (Itb3.profiles ())

(* Profiles whose canonical name begins with "streaming-" route
   through the one-shot streaming buffered pair instead of the
   Single Message pair. *)
let is_streaming_profile profile =
  let prefix = "streaming-" in
  String.length profile >= String.length prefix
  && String.sub profile 0 (String.length prefix) = prefix

(* Recursively create the parent directory of [path] (mkdir -p).
   OCaml's stdlib has no recursive mkdir and the eitb executable is
   not linked against Unix; shell out to /bin/mkdir. *)
let ensure_parent_dir path =
  let dir = Filename.dirname path in
  if dir <> "" && dir <> "." && dir <> "/" then
    let cmd = Printf.sprintf "mkdir -p %s" (Filename.quote dir) in
    let rc = Sys.command cmd in
    if rc <> 0 then
      raise (Itb3.ITB_error (-1, Printf.sprintf "mkdir -p failed (%d) for %s" rc dir))

let cmd_encrypt profile infile outfile =
  let plain = read_file infile in
  let pipe = Itb3.create profile () in
  let wire =
    if is_streaming_profile profile then Itb3.encrypt_stream_one_shot pipe plain
    else Itb3.encrypt_message pipe plain
  in
  ensure_parent_dir outfile;
  write_file outfile wire;
  prerr_endline (to_hex (Itb3.save pipe));
  Itb3.close pipe;
  Printf.printf "encrypted %s -> %s (%d -> %d bytes)\n" infile outfile
    (Bytes.length plain) (Bytes.length wire)

let cmd_decrypt profile blob_hex infile outfile =
  let blob = of_hex blob_hex in
  let wire = read_file infile in
  (* The profile shape travels inside the blob; the profile argument
     only selects the Single Message or streaming cipher pair. *)
  let pipe = Itb3.load blob in
  let plain =
    if is_streaming_profile profile then Itb3.decrypt_stream_one_shot pipe wire
    else Itb3.decrypt_message pipe wire
  in
  Itb3.close pipe;
  ensure_parent_dir outfile;
  write_file outfile plain;
  Printf.printf "decrypted %s -> %s (%d -> %d bytes)\n" infile outfile
    (Bytes.length wire) (Bytes.length plain)

let () =
  let argv = Array.to_list Sys.argv in
  let run () =
    (* Go-runtime pacing caps applied before any cipher work. *)
    Itb3.set_memory_limit (4 * 1024 * 1024 * 1024);
    Itb3.set_gc_percent 100;
    match List.tl argv with
    | [ "version" ] -> cmd_version ()
    | [ "profiles" ] -> cmd_profiles ()
    | [ "encrypt"; profile; infile; outfile ] -> cmd_encrypt profile infile outfile
    | [ "decrypt"; profile; blob_hex; infile; outfile ] ->
        cmd_decrypt profile blob_hex infile outfile
    | _ ->
        prerr_endline usage;
        exit 2
  in
  try run () with
  | Itb3.ITB_error (st, msg) ->
      Printf.eprintf "eitb: status=%d (%s)%s\n" st (Itb3.status_label st)
        (if msg = "" then "" else ": " ^ msg);
      exit 1
  | Sys_error msg ->
      Printf.eprintf "eitb: %s\n" msg;
      exit 1
