
field_list ipv4_checksum_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.diffserv;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
} 

field_list_calculation ipv4_checksum {
    input { 
        ipv4_checksum_list; 
    }
    algorithm : csum16;
    output_width : 16;
} 

calculated_field ipv4.hdrChecksum {
    verify ipv4_checksum if (ipv4.ihl ==5);
    update ipv4_checksum if (ipv4.ihl ==5);
}