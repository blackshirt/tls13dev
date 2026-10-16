module main

import handshake

fn main() {
	mut h := new_client_handshake('example.com', [])!
	h.create_client_hello()!
	sid := h.config.session_id.clone()
	body := build_hrr_body(sid, none, [u8(1), 2, 3, 4])!
	followups, _ := h.process_server_hello(hrr_record(body))!
	ch2 := followups[0].payload
	for i := 0; i < ch2.len - 15; i++ {
		if ch2[i] == 0x00 && ch2[i+1] == 0x0a {
			println('ok')
			return
		}
	}
	println('no')
}
