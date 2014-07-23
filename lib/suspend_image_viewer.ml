open Suspend_image

let opt_debug = ref true
let msg ~prefix s  = Printf.printf "%s: %s\n%!" prefix s
let debug fmt = Printf.ksprintf (fun s -> if !opt_debug then msg ~prefix:"debug" s) fmt
let error fmt = Printf.ksprintf (msg ~prefix:"error") fmt

let rec para_of_string max_length s =
	let slen = String.length s in
	let rec inner acc i =
		if i = slen then acc
		else
			let line_length = min (slen - i) max_length in
			let line = String.sub s i line_length in
			inner (line::acc) (i + line_length)
	in
	inner [] 0 |> List.rev

let strings_of_xenops_record max_length r =
	let open Xenops_record in
	let open Printf in
	let unbox = function Some x -> x | None -> "None" in
	sprintf "Time suspended: %s" r.time
	:: sprintf "Word size on source: %d" r.word_size
	:: sprintf "VM record: %s"
		match r.vm_str with Some x -> para_of_string max_length x | _ -> "None"
	:: sprintf "XenStore domain tree: %s"
		match r.xs_subtree with
		| Some x ->
			List.map (fun (k, v) -> sprintf "%s = \"%s\"" k v) x
			|> String.concat "\n"
		| None -> "None"

let verify_libxc_v2_record fd =
	let fd_uuid = Uuidm.(to_string (create `V4)) in
	let path = !Path.verify_libxc_v2 in
	let args = ["--in"; fd_uuid; "--syslog"] in
	begin
		try Unix.(access path [X_OK])
		with _ -> failwith (Printf.sprintf "Executable not found: %s" path)
	end;
	let pid =
		Forkhelpers.safe_close_and_exec
			None (Some Unix.stdout) (Some Unix.stderr) [fd_uuid, fd]
			path args
	in
	match Forkhelpers.waitpid pid with
	| _, Unix.WEXITED 0 -> ()
	| _ -> failwith "Failed to verify Libxc v2 record"

let parse_layout fd =
	debug "Reading save signature...";
	match read_save_signature fd with
	| `Error e ->
		error "Error reading save signature: %s" e;
		failwith e
	| `Ok Legacy -> []
	| `Ok Structured ->
		let open Suspend_image.M in
		let rec aux acc =
			debug "Reading header...";
			read_header fd >>= fun h ->
			debug "Read header <%s>" (string_of_header h);
			debug "Dummy-processing record...";
			begin match h with
			| Xenops, len ->
				let record_strings = Io.read fd (Io.int_of_int64_exn len)
				|> Xenops_record.of_string
				|> strings_of_xenops_record in
				aux (h,record_strings::acc)
			| Libxc, _ ->
				verify_libxc_v2_record fd;
				aux (h,[]::acc)
			| Qemu_trad, len ->
				Io.read fd (Io.int_of_int64_exn len) |> ignore;
				aux (h,[]::acc)
			| End_of_image, _ -> return (h::acc)
			| _ -> failwith "Unsupported"
			end
		in
		match aux [] with
		| `Ok hs -> List.rev hs
		| `Error e ->
			failwith (Printf.sprintf "Error parsing image: %s" (Printexc.to_string e))

let print_layout records =
	let module S = String in
	let default_width = 10 in
	let max_header_word_length =
		List.map (fun h -> string_of_header h |> S.length) headers
		|> List.fold_left max default_width
	in
	let left_pad = "| " and right_pad = " |" in
	let col_width = max_header_word_length + (S.length left_pad) + (S.length right_pad) in
	Printf.printf "+%s+\n" (S.make (col_width - 2) '=');
	let print_row s =
		let filled_space = List.map S.length [left_pad; s; right_pad]
		|> List.fold_left (+) 0 in
		let padding = S.make (col_width - filled_space) ' ' in
		Printf.printf "%s%s%s%s\n" left_pad h_str padding right_pad
	in
	let rec inner = function
	| [] -> ()
	| (header, contents)::rs ->
		print_row string_of_header h;
		Printf.printf "+%s+\n" (S.make (col_width - 2) '-');
		List.map print_row contents;
		Printf.printf "+%s+\n" (S.make (col_width - 2) '=');
		inner hs
	in
	inner records

let print_image path =
	Unixext.with_file path [Unix.O_RDONLY] 0o400 (fun fd ->
		print_layout (parse_layout fd)
	)

(* Command line interface *)

open Cmdliner

let path =
	let doc = "Path to the suspend image device" in
	Arg.(required & pos 0 (some file) None & info [] ~docv:"PATH" ~doc)

let cmd =
	let doc = "Print the layout of a suspend image" in
	let man = [] in
	Term.(pure print_image $ path),
	Term.info "suspend_image_viewer" ~version:"0.0.1" ~doc ~man

let () = match Term.eval cmd with `Error _ -> exit 1 | _ -> exit 0
