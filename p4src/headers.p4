#include "queueing_metadata.p4"
#include "intrinsic_metadata.p4"

header_type queue_t{
    fields {
	queue1: 8;
	queue2: 8;
	queue3: 8;
	queue4: 8;
    }
}

header queue_t queue_head;

header_type ethernet_t {
	fields {
		dstAddr: 48;
		srcAddr: 48;
		etherType: 16;
	}
}

header ethernet_t ethernet;

header_type arp_t {
	fields {
		hw_type: 16;
		protocol_type: 16;
		hw_Addr_length: 8;
		protocol_Addr_length: 8;
		operation: 16;
		sender_hw_Addr: 48;
		sender_ip_Addr: 32;
		target_hw_Addr: 48;
		target_ip_Addr: 32;
	}
}

header arp_t arp;

header_type ipv4_t {
	fields {
		version: 4;
		ihl: 4;
		diffserv: 8;
		totalLen: 16;
		identification: 16;
		flags: 3;
		fragOffset: 13;
		ttl: 8;
		protocol: 8;
		hdrChecksum: 16;
		srcAddr: 32;
		dstAddr: 32;
	}

}

header ipv4_t ipv4;

header_type option_t {
	fields {
		optins: 24;
		padding: 8;
	}
}

header option_t option;

header_type udp_t {
	fields {
		src_port: 16;
		dst_port: 16;
		pkt_length: 16;
		checksum: 16;
	}
}

header udp_t udp;

header_type tcp_t {
	fields {
		src_port: 16;
		dst_port: 16;
		seq_no: 32;
		ack_nu: 32;
		data_offset: 4;
		res: 4;
		flags: 8;
		window: 16;
		checksum: 16;
		urgent_ptr: 16;
	}
}

header tcp_t tcp;

header_type svef_t {
	fields {
		lid: 8;
		tid: 8;
		qid: 8;
		l: 1;
		ty: 2;
		d: 1;
		t: 1;
		two: 1;
		to_drop: 1;
		res: 1;
		naluid: 32;
		total_size: 16;
		frame_num: 16;
		rdo: 32;
	}
}

header svef_t svef;
