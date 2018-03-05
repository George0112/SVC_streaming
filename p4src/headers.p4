header_type ingress_intrinsic_metadata_t {
    fields {
        resubmit_flag : 1;              // flag distinguishing original packets
                                        // from resubmitted packets.

        ingress_global_timestamp : 48;     // global timestamp (ns) taken upon
                                        // arrival at ingress.

        mcast_grp : 16;                 // multicast group id (key for the
                                        // mcast replication table)

        deflection_flag : 1;            // flag indicating whether a packet is
                                        // deflected due to deflect_on_drop.
        deflect_on_drop : 1;            // flag indicating whether a packet can
                                        // be deflected by TM on congestion drop

        enq_congest_stat : 2;           // queue congestion status at the packet
                                        // enqueue time.

        deq_congest_stat : 2;           // queue congestion status at the packet
                                        // dequeue time.

        mcast_hash : 13;                // multicast hashing

        egress_rid : 16;                // Replication ID for multicast

        lf_field_list : 32;             // Learn filter field list

        priority : 3;                   // set packet priority

        ingress_cos: 3;                 // ingress cos

        packet_color: 2;                // packet color

        qid: 5;                         // queue id
    }
}

metadata ingress_intrinsic_metadata_t intrinsic_metadata;

header_type queueing_metadata_t {
    fields {
        enq_timestamp: 48;

        enq_qdepth: 16;

        deq_timedelta: 32;

        deq_qdepth: 16;

    }
}

metadata queueing_metadata_t queueing_metadata;

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
		tragOffset: 13;
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
		res: 2;
		naluid: 32;
		total_size: 16;
		frame_num: 16;
	}
}

header svef_t svef;
