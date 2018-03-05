parser start {
    return parse_ethernet;
}

parser parse_ethernet {
	extract(ethernet);
	return select(ethernet.etherType){
		0x0806: parse_arp;
		0x0800: parse_ipv4;
		default: ingress;
	}
}

parser parse_arp {
	extract(arp);
	return ingress;
}

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.protocol){
		//0x11: parse_udp;
		default: ingress;
	}
}

parser parse_option {
	extract(option);
	return parse_udp;
}

parser parse_udp {
	extract(udp);
	return parse_svef;
}

parser parse_svef {
	extract(svef);
	return ingress;
}
