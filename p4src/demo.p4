/*
 * Copyright 2017-present Open Networking Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

 /*
  * This program describes a pipeline implementing a very simple
  * tunneling protocol called MyTunnel. The pipeline defines also table called
  * t_l2_fwd that provides basic L2 forwarding capabilities and actions to
  * send packets to the controller. This table is needed to provide
  * compatibility with existing ONOS applications such as Proxy-ARP, LLDP Link
  * Discovery and Reactive Forwarding.
  */

#include <core.p4>
#include <v1model.p4>

#define MAX_PORTS 255

const bit<16> ETH_TYPE_MYTUNNEL = 0x1212;
const bit<16> ETH_TYPE_IPV4 = 0x800;
const bit<16> ETH_TYPE_BIER = 0x6666;

const bit<32> IPV4_MULTICAST = 0xED000001;

typedef bit<9> port_t;
const port_t CPU_PORT = 255;

//------------------------------------------------------------------------------
// HEADERS
//------------------------------------------------------------------------------

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header my_tunnel_t {
    bit<16> proto_id;
    bit<32> tun_id;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> len;
    bit<16> identification;
    bit<3>  flags;
    bit<13> frag_offset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
}

header svef_t {
    bit<8> lid;
    bit<8> tid;
    bit<8> qid;
    bit<1> l;
    bit<2> ty;
    bit<1> d;
    bit<1> t;
    bit<1> two;
    bit<2> res;
    bit<32> naluid;
    bit<16> totalSize;
    bit<16> frameNum;
}

header intrinsic_metadata_t {
    bit<4>  mcast_grp;
    bit<4>  egress_rid;
    bit<16> mcast_hash;
    bit<1>  recirculate_flag;
    bit<1>  resubmit_flag;
    bit<6>  pad;
}    

header bier_metadata_t {
    bit<32>  k_pos;
    bit<32> bs_remaining;
    bit<1>  needs_cloning;
    bit<1>  decap;
}

/*****

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |              BIFT-id                  | TC  |S|     TTL       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |Nibble |  Ver  |  BSL  |              Entropy                  |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |OAM|Rsv|    DSCP   |   Proto   |            BFIR-id            |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                BitString  (first 32 bits)                     ~
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ~                                                               ~
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     ~                BitString  (last 32 bits)                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*****/

// BIER header
header bier_t {
    /*bit<20> bift-id;
    bit<3> tc;
    bit<1> s;
    bit<8> ttl;
    bit<4> nibble;
    bit<4> ver;
    bit<4> bsl;
    bit<20> entropy;
    bit<2> oam;
    bit<2> rsv;
    bit<6> dscp;
    bit<6> proto;
    bit<16> bfir-id;*/
    bit<32> bitString;
}

// Packet-in header. Prepended to packets sent to the controller and used to
// carry the original ingress port where the packet was received.
@controller_header("packet_in")
header packet_in_header_t {
    bit<9> ingress_port;
}

// Packet-out header. Prepended to packets received by the controller and used
// to tell the switch on which port this packet should be forwarded.
@controller_header("packet_out")
header packet_out_header_t {
    bit<32> ip_dst_addr;
    bit<32> ip_src_addr;
    bit<48> mac_dst_addr;
    bit<48> mac_src_addr;
    bit<32> udp_dst_port;
    bit<32> udp_src_port;
    bit<9> egress_port;
}

// For convenience we collect all headers under the same struct.
struct headers_t {
    ethernet_t ethernet;
    my_tunnel_t my_tunnel;
    bier_t bier;
    bier_metadata_t bier_metadata;
    ipv4_t ipv4;
    udp_t udp;
    svef_t svef;
    packet_out_header_t packet_out;
    packet_in_header_t packet_in;
}

// Metadata can be used to carry information from one table to another.
struct metadata_t {
    // Empty. We don't use it in this program.
}

//------------------------------------------------------------------------------
// PARSER
//------------------------------------------------------------------------------

parser c_parser(packet_in packet,
                  out headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata) {

    // A P4 parser is described as a state machine, with initial state "start"
    // and final one "accept". Each intermediate state can specify the next
    // state by using a select statement over the header fields extracted.
    state start {
        transition select(standard_metadata.ingress_port) {
            CPU_PORT: parse_packet_out;
            default: parse_ethernet;
        }
    }

    state parse_packet_out {
        packet.extract(hdr.packet_out);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETH_TYPE_BIER: parse_bier;
            ETH_TYPE_MYTUNNEL: parse_my_tunnel;
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_bier {
        packet.extract(hdr.bier);
        transition parse_ipv4;
    }

    state parse_my_tunnel {
        packet.extract(hdr.my_tunnel);
        transition select(hdr.my_tunnel.proto_id) {
            ETH_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            0x11: parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition parse_svef;
    }

    state parse_svef{
        packet.extract(hdr.svef);
        transition accept;
    }
}

//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------

control c_ingress(inout headers_t hdr,
                    inout metadata_t meta,
                    inout standard_metadata_t standard_metadata) {

    // We use these counters to count packets/bytes received/sent on each port.
    // For each counter we instantiate a number of cells equal to MAX_PORTS.
    counter(MAX_PORTS, CounterType.packets_and_bytes) tx_port_counter;
    counter(MAX_PORTS, CounterType.packets_and_bytes) rx_port_counter;

    register<bit<8>>(1) level;
    bit<8> lRead = 0;

    action send_to_cpu() {
        standard_metadata.egress_spec = CPU_PORT;
        // Packets sent to the controller needs to be prepended with the
        // packet-in header. By setting it valid we make sure it will be
        // deparsed on the wire (see c_deparser).
        hdr.packet_in.setValid();
        hdr.packet_in.ingress_port = standard_metadata.ingress_port;
    }

    action set_out_port(port_t port) {
        // Specifies the output port for this packet by setting the
        // corresponding metadata.
        standard_metadata.egress_spec = port;
    }

    action go_to_2(){
        standard_metadata.egress_spec = 2;
    }

    action _drop() {
        mark_to_drop();
    }

    action bier_ingress(bit<32> bm) {
        hdr.bier.setValid();
        hdr.bier.bitString = bm;
        hdr.ethernet.ether_type = ETH_TYPE_BIER;
    }

    action save_pos(bit<32> k_pos, bit<32> bm) {
        hdr.bier_metadata.bs_remaining = hdr.bier.bitString & ~ bm;
        hdr.bier.bitString = bm;
        hdr.bier_metadata.k_pos = k_pos;
        clone3(CloneType.I2E, 1024, {hdr.bier_metadata});
    }

    action remove_bier(bit<32> ip, bit<48> dmac, bit<9> port) {
        hdr.ethernet.ether_type = ETH_TYPE_IPV4;
        hdr.ipv4.dst_addr = ip;
        hdr.ethernet.dst_addr = dmac;
        standard_metadata.egress_spec = port;
        hdr.bier.setInvalid();
    }

    action set_bier_meta(){
            hdr.bier.setValid();
            hdr.bier.bitString = hdr.bier_metadata.bs_remaining;
            hdr.ethernet.ether_type = ETH_TYPE_BIER;        
    }

    action my_tunnel_ingress(bit<32> tun_id) {
        hdr.my_tunnel.setValid();
        hdr.my_tunnel.tun_id = tun_id;
        hdr.my_tunnel.proto_id = hdr.ethernet.ether_type;
        hdr.ethernet.ether_type = ETH_TYPE_MYTUNNEL;
    }

    action my_tunnel_egress(bit<9> port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.ether_type = hdr.my_tunnel.proto_id;
        hdr.my_tunnel.setInvalid();
    }

    action write_level(bit<8> l){
        level.write(0, l);
    }

    action read_level(out bit<8> l) {
        level.read(l, 0);
    }

    // Table counter used to count packets and bytes matched by each entry of
    // t_l2_fwd table.
    direct_counter(CounterType.packets_and_bytes) l2_fwd_counter;

    table t_l2_fwd {
        key = {
            standard_metadata.ingress_port  : ternary;
            hdr.ethernet.dst_addr           : ternary;
            hdr.ethernet.src_addr           : ternary;
            hdr.ethernet.ether_type         : ternary;
        }
        actions = {
            set_out_port;
            send_to_cpu;
            _drop;
            NoAction;
        }
        default_action = NoAction();
        counters = l2_fwd_counter;
    }

    table t_bier_ingress {
        key = {
            hdr.ipv4.dst_addr: exact;
        }
        actions = {
            bier_ingress;
            //send_to_cpu;
        }
        //default_action = NoAction();
    }

    table t_find_pos {
        key = {
            hdr.bier.bitString: lpm;
        }
        actions = {
            save_pos;
            go_to_2;
            _drop;
        }
        default_action = _drop();
    }

    table t_bier_fwd {
        key = {
            hdr.bier.bitString: exact;
        }
        actions = {
            set_out_port;
            remove_bier;
            go_to_2;
            _drop;
        }
        default_action = go_to_2();
    }

    table t_set_bier_meta {
        actions = {
            set_bier_meta;
        }
        default_action = set_bier_meta();
    }

    table t_tunnel_ingress {
        key = {
            hdr.ipv4.dst_addr: lpm;
        }
        actions = {
            my_tunnel_ingress;
            _drop;
        }
        default_action = _drop();
    }

    table t_tunnel_fwd {
        key = {
            hdr.my_tunnel.tun_id: exact;
        }
        actions = {
            set_out_port;
            my_tunnel_egress;
            _drop;
        }
        default_action = _drop();
    }

    table t_drop {
        key = {

        }
        actions = {
            _drop();
        }
        default_action = _drop();
    }

    table t_write_level {
        key = {

        }
        actions = {
            write_level();
        }
        default_action = write_level();
    }

    table t_read_level {
        key ={

        }
        actions = {
            read_level(lRead);
        }
        default_action = read_level(lRead);
    }

    // Defines the processing applied by this control block. You can see this as
    // the main function applied to every packet received by the switch.
    apply {
        t_read_level.apply();    
        if(standard_metadata.instance_type != 0) {
            t_set_bier_meta.apply();
        }
        if (standard_metadata.ingress_port == CPU_PORT) {
            // Packet received from CPU_PORT, this is a packet-out sent by the
            // controller. Skip table processing, set the egress port as
            // requested by the controller (packet_out header) and remove the
            // packet_out header.
            if(hdr.packet_out.egress_port == 0){
                hdr.bier.setValid();
                hdr.bier.bitString = hdr.packet_out.ip_dst_addr;
                hdr.ethernet.ether_type = ETH_TYPE_BIER;
            }else{
                if(hdr.packet_out.ip_dst_addr != 0)
                    hdr.ipv4.dst_addr = hdr.packet_out.ip_dst_addr;
                if(hdr.packet_out.ip_src_addr != 0)
                    hdr.ipv4.src_addr = hdr.packet_out.ip_src_addr;
                if(hdr.packet_out.mac_dst_addr != 0)
                    hdr.ethernet.dst_addr = hdr.packet_out.mac_dst_addr;
                if(hdr.packet_out.mac_src_addr != 0)
                    hdr.ethernet.src_addr = hdr.packet_out.mac_src_addr;
                if(hdr.packet_out.udp_dst_port != 0)
                    hdr.udp.dst_port = hdr.packet_out.udp_dst_port[15:0];
                if(hdr.packet_out.udp_src_port != 0)
                    hdr.udp.src_port = hdr.packet_out.udp_src_port[15:0];
                if(hdr.packet_out.egress_port != 0)
                standard_metadata.egress_spec = hdr.packet_out.egress_port;
            }
            //standard_metadata.egress_spec = 1;
            hdr.packet_out.setInvalid();
        } else {
            // Packet received from data plane port.
            // Applies table t_l2_fwd to the packet.
            if (t_l2_fwd.apply().hit) {
                // Packet hit an entry in t_l2_fwd table. A forwarding action
                // has already been taken. No need to apply other tables, exit
                // this control block.
                return;
            }
            // It's an IPV4 packet, try if it's an multicast packet.
            // If it's a multicast, push bier header into it.
            // if (hdr.ipv4.isValid() && !hdr.bier.isValid()) {
            //         t_bier_ingress.apply();
            // }
        }

        if(hdr.bier.isValid()){
            if(t_find_pos.apply().hit){
                t_bier_fwd.apply();
            }
        }

        if(hdr.svef.isValid()){
            if(lRead > 0 && hdr.svef.qid > lRead){
                t_drop.apply();
            }
        }

        if(hdr.ipv4.isValid())
            hdr.ipv4.ttl = hdr.ipv4.ttl -1;

        // Update port counters at index = ingress or egress port.
        if (standard_metadata.egress_spec < MAX_PORTS) {
            tx_port_counter.count((bit<32>) standard_metadata.egress_spec);
        }
        if (standard_metadata.ingress_port < MAX_PORTS) {
            rx_port_counter.count((bit<32>) standard_metadata.ingress_port);
        }
    }
}

//------------------------------------------------------------------------------
// EGRESS PIPELINE
//------------------------------------------------------------------------------

control c_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata) {

    apply{
        if(standard_metadata.instance_type == 1) recirculate({hdr.bier_metadata});
        //if(standard_metadata.instance_type == 1) recirculate({});
    }
}

//------------------------------------------------------------------------------
// CHECKSUM HANDLING
//------------------------------------------------------------------------------

control c_verify_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        // Nothing to do here, we assume checksum is always correct.
    }
}

control c_compute_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        // No need to compute checksum as we do not modify packet headers.
    }
}

//------------------------------------------------------------------------------
// DEPARSER
//------------------------------------------------------------------------------

control c_deparser(packet_out packet, in headers_t hdr) {
    apply {
        // Emit headers on the wire in the following order.
        // Only valid headers are emitted.
        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.bier);
        packet.emit(hdr.my_tunnel);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.svef);
    }
}

//------------------------------------------------------------------------------
// SWITCH INSTANTIATION
//------------------------------------------------------------------------------

V1Switch(c_parser(),
         c_verify_checksum(),
         c_ingress(),
         c_egress(),
         c_compute_checksum(),
         c_deparser()) main;