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



header_type metadata_t {
    fields {
        pos: 7;
    }
}

header metadata_t metadata_pos;

header_type queue_t {
    fields {
        queue1   : 8;
        queue2   : 8;
        queue3   : 8;
        queue4   : 8;
        egress_queue: 8;
    }
}

header queue_t queue_head;

header_type ethernet_t {
    fields {
        dst_addr   : 48;
        src_addr   : 48;
        ether_type : 16;
    }
}

header ethernet_t ethernet_head;

header_type ipv4_t {
    fields {
        version         : 4;
        ihl             : 4;
        diffserv        : 8;
        totalLen        : 16;
        identification  : 16;
        flags           : 3;
        fragOffset      : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr : 32;

    }
}

header ipv4_t ipv4_head;

header_type udp_t {
    fields {
        src_port      : 16;
        dst_port      : 16;
        udp_len       : 16;
        upd_checksum  : 16;
    }
}

header udp_t udp_head;

header_type tcp_t {
    fields{
        srcPort : 16;
        dstPort : 16;
        seqNo : 32;
        ackNo : 32;
        dataOffset : 4;
        res : 4;
        flags : 8;
        window : 16;
        checksum : 16;
        urgentPtr : 16;
    }
}

header tcp_t tcp_head;

header_type queueing_metadata_t {
    fields {
        enq_timestamp   : 8;
        enq_qdepth      : 8;
        deq_timedelta   : 8;
        deq_qdepth      : 8;
    }

}

header queueing_metadata_t queueing_metadata;

header_type nalu_t {
    fields {
        lid    : 8;
        tid    : 8;
        qid    : 8;
        l      : 1;
        ty     : 2;
        d      : 1;
        t      : 1;
        dou    : 1;
        res    : 2;
        naluid : 32;
        total_size : 16;
        frame_number : 16;


    }
}

header nalu_t nalu_head;

field_list ipv4_checksum_list {
    ipv4_head.version;
    ipv4_head.ihl;
    ipv4_head.diffserv;
    ipv4_head.totalLen;
    ipv4_head.identification;
    ipv4_head.flags;
    ipv4_head.fragOffset;
    ipv4_head.ttl;
    ipv4_head.protocol;
    ipv4_head.srcAddr;
    ipv4_head.dstAddr;
} 

field_list_calculation ipv4_checksum {
    input { 
        ipv4_checksum_list; 
    }
    algorithm : csum16;
    output_width : 16;
} 

calculated_field ipv4_head.hdrChecksum {
    verify ipv4_checksum if (ipv4_head.ihl ==5);
    update ipv4_checksum if (ipv4_head.ihl ==5);
}

parser start {
    return parse_ethernet_head;
}

parser parse_ethernet_head {
    extract(ethernet_head);
    return select(latest.ether_type) {
        0: ingress;
        default: parse_ipv4_head;
    }
}

parser parse_ipv4_head {
    extract(ipv4_head);
    return select(latest.fragOffset, latest.ihl, latest.protocol) {
        default: ingress;
        0x0000511 : parse_udp_head;
        0x0000506 : parse_tcp_head;
    }
}

parser parse_tcp_head {
    extract(tcp_head);
    return ingress;
}

parser parse_udp_head {
    extract(udp_head);
    return parse_nalu_head;
    
}

parser parse_nalu_head {
    extract(nalu_head);
    return ingress;
}

action _drop() {

    drop();
}


action route() {
    modify_field(standard_metadata.egress_spec, 1);
}

action route2() {
    modify_field(standard_metadata.egress_spec, 2);
}

action route3() {
    modify_field(standard_metadata.egress_spec, 3);
}

action read_pos() {

    modify_field_rng_uniform(metadata_pos.pos, 1, 100);
}

action set_queue1(){
    modify_field(queue_head.egress_queue, queue_head.queue1);
}
action set_queue2(){
    modify_field(queue_head.egress_queue, queue_head.queue2);
}
action set_queue3(){
    modify_field(queue_head.egress_queue, queue_head.queue3);
}
action set_queue4(){
    modify_field(queue_head.egress_queue, queue_head.queue4);
}



table set_queue_depth {
    reads {
        standard_metadata.egress_spec: exact;
    }
    actions {
        set_queue1;
        set_queue2;
        set_queue3;
        set_queue4;
    }
}



table set_pos {
    reads {
        nalu_head: valid;
        nalu_head.qid: exact;
    }
    actions {
        read_pos;
    }
}



table drop_pkt {
    reads {
        nalu_head: valid;
        nalu_head.qid: exact;
    }
    actions {
        _drop;
    }
}

table route_frag {
    reads {

        ipv4_head.flags : exact;
    }
    actions {
        route;
        route2;
        route3;
    }
}

table route_pkt {
    reads {
        ipv4_head : valid;
        ipv4_head.dstAddr : lpm;
    }
    actions {
        route;
        route2;
        route3;
    }
}



control ingress {
    

    apply(set_pos);

    if(valid(nalu_head)){
        apply(set_queue_depth);
        if (nalu_head.qid == 2){
            apply(drop_pkt);
            /*
            if (queue_head.egress_queue > 60){
                
                    apply(drop_pkt);

            }
            else if (queue_head.egress_queue > 59){
                if(metadata_pos.pos > 25){
                    apply(drop_pkt);
                }
            }
            else if (queue_head.egress_queue > 58){
                if(metadata_pos.pos > 50){
                    apply(drop_pkt);
                }
            }
            else if (queue_head.egress_queue > 57){
                if(metadata_pos.pos > 75){
                    apply(drop_pkt);
                }
            }    
            */
        }
        else if (nalu_head.qid == 1){
                apply(route_pkt);
            /*
            if (queue_head.egress_queue > 61){
                    apply(drop_pkt);
                
            }
            else if (queue_head.egress_queue > 60){
                if(metadata_pos.pos > 50){
                    apply(drop_pkt);
                }
            }
            */       
        }
    }
    

}

control egress {
    // leave empty
}

register drop_pos {
    width : 7;
    instance_count : 3;
}
