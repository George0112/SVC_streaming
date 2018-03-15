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
    drop();
}

action action_pkt(port) {
	modify_field(standard_metadata.egress_spec, port);
}

action action_arp(port) {
	modify_field(standard_metadata.egress_spec, port);
}

action _no_action() {
}

table route_arp {
	reads {
		arp.sender_ip_Addr: lpm;
	}
	actions {
		action_arp;
	}
	size: 2;
}

table route_pkt {
    reads {
        ipv4.dstAddr: lpm;
    }
    actions {
        _drop;
        action_pkt;
    }
    size: 3;
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

control ingress {
	if(ethernet.etherType == 0x0806) {
		apply(route_arp);
	}/*
	else if(valid(ipv4)){
			if(svef.qid >= 0){
				apply(route_pkt);
			} else {
				apply(table_drop);
			}
		
		if(ipv4.protocol == 0x01){
			apply(route_pkt);
		}else if(ipv4.protocol == 0x11){
			if(svef.d == 0){
				apply(route_pkt);
			}
		}
	}
	else if(valid(svef)){
		if(svef.qid == 2){
			apply(route_pkt);
		}
		else{
			apply(table_drop);
		}
	}*/
	else{
		apply(route_pkt);
	}
}

control egress {
    // leave empty
}
