/*
Copyright 2013-present Barefoot Networks, Inc. 

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "headers.p4"
#include "parsers.p4"
#include "ipv4_checksum.p4"

action _drop() {
	//register_write(register_rdo, 0, svef);
    drop();
	//modify_field(standard_metadata.egress_port, 511);
}

action action_pkt(port) {
	modify_field(standard_metadata.egress_spec, port);
}

action action_arp(port) {
	modify_field(standard_metadata.egress_spec, port);
}

action _no_action() {
}

action rewrite_mac(smac) {
    modify_field(ethernet.srcAddr, smac);
	modify_field(ipv4.ttl, queueing_metadata.deq_qdepth);
}

register register_rdo{
	layout: svef_t;
	instance_count: 10;
}

table route_arp {
	reads {
		arp.sender_ip_Addr: lpm;
	}
	actions {
		action_arp;
	}
	size: 4;
}

table route_pkt {
    reads {
        ipv4.dstAddr: lpm;
    }
    actions {
        _drop;
        action_pkt;
    }
    size: 8;
}

table table_drop {
	reads {
		ethernet.srcAddr: valid;
	}
	actions {
		_drop;
		_no_action;
	}
}

table send_frame {
    reads {
        standard_metadata.egress_port: exact;
    }
    actions {
        rewrite_mac;
        _drop;
    }
    size: 256;
}

control ingress {
	if(ethernet.etherType == 0x0806) {
		apply(route_arp);
	}
	else apply(route_pkt);
	if(valid(udp)){
		if(udp.dst_port >= 4455){
			if(standard_metadata.egress_spec == 2){
			if(queue_head.queue2 > 50){
				if(svef.qid > 0){
					apply(table_drop);
				}
			}else if(queue_head.queue2 > 30){
				if(svef.qid > 1){
					apply(table_drop);
				}
			}else if(queue_head.queue2 > 1){
				if(svef.qid > 2){
					apply(table_drop);
				}
			}
			}
			else if(standard_metadata.egress_spec == 4){
			if(queue_head.queue4 > 50){
				if(svef.qid > 0){
					apply(table_drop);
				}
			}else if(queue_head.queue4 > 30){
				if(svef.qid > 1){
					apply(table_drop);
				}
			}else if(queue_head.queue4 > 1){
				if(svef.qid > 2){
					apply(table_drop);
				}
			}
			}
		}
	}
}

control egress {
	apply(send_frame);
}
