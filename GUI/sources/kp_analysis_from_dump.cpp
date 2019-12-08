// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#include "kp_analysis_from_dump.hpp"

Emitter sniffer_emitter;

uint16_t ntoh(uint16_t aim) {
    uint16_t first = 0, second = 0;
    first = static_cast<uint16_t>(65280) & aim;
    second = static_cast<uint16_t>(255) & aim;
    first >>= 8;
    second <<= 8;
    return first | second;
}

void mac_address::print_mac_addr(std::ostringstream& out) {
    out.unsetf(std::ios::dec);
    out.setf(std::ios::hex);
    out << '(' << static_cast<int>(byte1) << ':' << static_cast<int>(byte2) << ':' << static_cast<int>(byte3) << ':' << static_cast<int>(byte4) << ':' << static_cast<int>(byte5) << ':' << static_cast<int>(byte6) << ')';
    out.unsetf(std::ios::hex);
}

void ipv4_address::print_ip_addr(std::ostringstream& out) {
    out << static_cast<int>(byte1) << '.' << static_cast<int>(byte2) <<
        '.' << static_cast<int>(byte3) << '.' << static_cast<int>(byte4);
}

void ipv6_address::print_ip_addr(std::ostringstream& out) {
    size_t longest_count = 0;
    size_t longest_begin = 322;
    bool found = find_longest_zeros(longest_count, longest_begin);
    if (!found) {
        out.unsetf(std::ios::dec);
        out.setf(std::ios::hex);
        for (size_t i = 0; i < 16; i++) {
            out << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
            if (i % 2 == 1 && i != 15)
                out << ':';
        }
        out.unsetf(std::ios::hex);
    }
    else {
        out.unsetf(std::ios::dec);
        out.setf(std::ios::hex);
        for (size_t i = 0; i < 16; i++) {
            if (i == longest_begin) {
                if (longest_begin == 0)
                    out << "::";
                else
                    out << ':';
                i += 2 * longest_count - 1;
            }
            else {
                out << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[i]);
                if (i % 2 == 1 && i != 15)
                    out << ':';
            }
        }
        out.unsetf(std::ios::hex);
    }
}

bool ipv6_address::find_longest_zeros(size_t& longest_count, size_t& longest_begin) {
    size_t cur_count = 0;
    size_t cur_begin = 322;
    for (size_t i = 0; i < 16; i += 2) {
        if (bytes[i] + bytes[i + 1] == 0) {
            if (cur_begin != 322) {
                cur_count++;
            }
            else if (cur_begin == 322) {
                cur_begin = i;
                cur_count++;
            }
            if (cur_count > longest_count) {
                longest_count = cur_count;
                longest_begin = cur_begin;
            }
        }
        else {
            cur_count = 0;
            cur_begin = 322;
        }
    }
    if (longest_begin == 322 || longest_count == 1)
        return false;
    else
        return true;
}

void parce_udp(const uint8_t *pkt_data, uint32_t prev_header_len, std::ostringstream& out) {
    uint16_t sport, dport, len;
    udp_header* udp_h = (udp_header *)((uint8_t*)pkt_data + prev_header_len);
    sport = ntoh(udp_h->sport);
    dport = ntoh(udp_h->dport);
    len = ntoh(udp_h->len);
    out << "\nUser Datagram Protocol, Scr port: " << sport << ", Dst port: " << dport << ", Len: " << len << "\n";
}

void parce_tcp(const struct pcap_pkthdr *header, const uint8_t *pkt_data, uint32_t prev_header_len, std::ostringstream& out) {
    uint16_t sport, dport;
    tcp_header* tcp_h = (tcp_header *)((uint8_t*)pkt_data + prev_header_len);
    sport = ntoh(tcp_h->sport);
    dport = ntoh(tcp_h->dport);
    uint16_t different_info = ntoh(tcp_h->different_info);
    uint16_t window_size = ntoh(tcp_h->window_size);
    uint16_t tcp_header_len = (different_info >> 12) * 4;
    uint16_t tcp_payload_len = header->len - prev_header_len - tcp_header_len;
    out << "\nTransmission Control Protocol, Scr port: " << sport << ", Dst port: " << dport << ", Win: " << window_size << ", Payload len: " << tcp_payload_len << "\n";
}

void parce_igmp(const uint8_t *pkt_data, uint32_t prev_header_len, std::ostringstream& out) {
    igmp_header* igmp_h = (igmp_header *)((uint8_t*)pkt_data + prev_header_len);
    out << "\nInternet Group Management Protocol";
    if (igmp_h->type == 0x11) {
        out << "\nMembership query, ";
    }
    else if (igmp_h->type == 0x16 || igmp_h->type == 0x17) {
        out << " version 2\n";
        if (igmp_h->type == 0x16)
            out << "Membership report, ";
        else
            out << "Leave Group, ";
    }
    else if (igmp_h->type == 0x22) {
        out << " version 3\nMembership Report, ";
    }
    else {
        out << " unknown version\n";
    }
    out << "multicast address: ";
    igmp_h->group_address.print_ip_addr(out);
    out << std::endl;
}

void parce_icmp(const uint8_t *pkt_data, uint32_t prev_header_len, std::ostringstream& out) {
    icmp_header* icmp_h = (icmp_header*)((uint8_t*)pkt_data + prev_header_len);
    out << "\nInternet Control Message Protocol, ";
    if (static_cast<int>(icmp_h->type) == 0 && static_cast<int>(icmp_h->code) == 0) {
        out << "Echo Reply";
    }
    else if (static_cast<int>(icmp_h->type) == 3) {
        out << "Destination Unreachable (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "Destination network unreachable";
            break;
        case 1:
            out << "Destination host unreachable";
            break;
        case 2:
            out << "Destination protocol unreachable";
            break;
        case 3:
            out << "Destination port unreachable";
            break;
        case 4:
            out << "Fragmentation required";
            break;
        case 5:
            out << "Source route failed";
            break;
        case 6:
            out << "Destination network unknown";
            break;
        case 7:
            out << "Destination host unknown";
            break;
        case 8:
            out << "Source host isolated";
            break;
        case 9:
            out << "Network administratively prohibited";
            break;
        case 10:
            out << "Host administratively prohibited";
            break;
        case 11:
            out << "Network unreachable for ToS";
            break;
        case 12:
            out << "Host unreachable for ToS";
            break;
        case 13:
            out << "Communication administratively prohibited";
            break;
        case 14:
            out << "Host Precedence Violation";
            break;
        case 15:
            out << "Precedence cutoff in effect";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 5) {
        out << "Redirect Message (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "Redirect Datagram for the Network";
            break;
        case 1:
            out << "Redirect Datagram for the Host";
            break;
        case 2:
            out << "Redirect Datagram for the ToS & network";
            break;
        case 3:
            out << "Redirect Datagram for the ToS & host";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 8 && static_cast<int>(icmp_h->code) == 0) {
        out << "Echo Request";
    }
    else if (static_cast<int>(icmp_h->type) == 9 && static_cast<int>(icmp_h->code) == 0) {
        out << "Router Advertisement";
    }
    else if (static_cast<int>(icmp_h->type) == 10 && static_cast<int>(icmp_h->code) == 0) {
        out << "Router Solicitation";
    }
    else if (static_cast<int>(icmp_h->type) == 11) {
        out << "Time Exceeded (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "TTL expired in transit";
            break;
        case 1:
            out << "Fragment reassembly time exceeded";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 11) {
        out << "Parameter Problem: Bad IP header (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "Pointer indicates the error";
            break;
        case 1:
            out << "Missing a required option";
            break;
        case 2:
            out << "Bad length";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 13 && static_cast<int>(icmp_h->code) == 0) {
        out << "Timestamp";
    }
    else if (static_cast<int>(icmp_h->type) == 14 && static_cast<int>(icmp_h->code) == 0) {
        out << "Timestamp Reply";
    }
    else if (static_cast<int>(icmp_h->type) == 40) {
        out << "Photuris, Security failures";
    }
    else if (static_cast<int>(icmp_h->type) == 42 && static_cast<int>(icmp_h->code) == 0) {
        out << "Extended Echo Request";
    }
    else if (static_cast<int>(icmp_h->type) == 43) {
        out << "Extended Echo Reply (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "No Error";
            break;
        case 1:
            out << "Malformed Query";
            break;
        case 2:
            out << "No Such Interface";
            break;
        case 3:
            out << "No Such Table Entry";
            break;
        case 4:
            out << "Multiple Interfaces Satisfy Query";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else {
        out << "unknown type";
    }
    out << std::endl;
}

void parce_icmpv6(const uint8_t *pkt_data, uint32_t prev_header_len, std::ostringstream& out) {
    icmp_header* icmp_h = (icmp_header*)((uint8_t*)pkt_data + prev_header_len);
    out << "\nInternet Control Message Protocol v6, ";
    if (static_cast<int>(icmp_h->type) == 1) {
        out << "Destination unreachable (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "no route to destination";
            break;
        case 1:
            out << "communication with destination administratively prohibited";
            break;
        case 2:
            out << "beyond scope of source address";
            break;
        case 3:
            out << "address unreachable";
            break;
        case 4:
            out << "port unreachable";
            break;
        case 5:
            out << "source address failed ingress/egress policy";
            break;
        case 6:
            out << "reject route to destination";
            break;
        case 7:
            out << "Error in Source Routing Header";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 2 && static_cast<int>(icmp_h->code) == 0) {
        out << "Packet Too Big";
    }
    else if (static_cast<int>(icmp_h->type) == 3) {
        out << "Time exceeded (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "hop limit exceeded in transit";
            break;
        case 1:
            out << "fragment reassembly time exceeded";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 4) {
        out << "Parameter problem (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "erroneous header field encountered";
            break;
        case 1:
            out << "unrecognized Next Header type encountered";
            break;
        case 2:
            out << "unrecognized IPv6 option encountered";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 128 && static_cast<int>(icmp_h->code) == 0) {
        out << "Echo Request";
    }
    else if (static_cast<int>(icmp_h->type) == 129 && static_cast<int>(icmp_h->code) == 0) {
        out << "Echo Reply";
    }
    else if (static_cast<int>(icmp_h->type) == 130 && static_cast<int>(icmp_h->code) == 0) {
        out << "Multicast Listener Query";
    }
    else if (static_cast<int>(icmp_h->type) == 131 && static_cast<int>(icmp_h->code) == 0) {
        out << "Multicast Listener Report";
    }
    else if (static_cast<int>(icmp_h->type) == 132 && static_cast<int>(icmp_h->code) == 0) {
        out << "Multicast Listener Done";
    }
    else if (static_cast<int>(icmp_h->type) == 133 && static_cast<int>(icmp_h->code) == 0) {
        out << "Router Solicitation";
    }
    else if (static_cast<int>(icmp_h->type) == 134 && static_cast<int>(icmp_h->code) == 0) {
        out << "Router Advertisement";
    }
    else if (static_cast<int>(icmp_h->type) == 135 && static_cast<int>(icmp_h->code) == 0) {
        out << "Neighbor Solicitation";
    }
    else if (static_cast<int>(icmp_h->type) == 136 && static_cast<int>(icmp_h->code) == 0) {
        out << "Neighbor Advertisement";
    }
    else if (static_cast<int>(icmp_h->type) == 137 && static_cast<int>(icmp_h->code) == 0) {
        out << "Redirect Message";
    }
    else if (static_cast<int>(icmp_h->type) == 138) {
        out << "Router Renumbering (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "Router Renumbering Command";
            break;
        case 1:
            out << "Router Renumbering Result";
            break;
        case 255:
            out << "Sequence Number Reset";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 139) {
        out << "ICMP Node Information Query (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "The Data field contains an IPv6 address which is the Subject of this Query";
            break;
        case 1:
            out << "The Data field contains a name which is the Subject of this Query, or is empty, as in the case of a NOOP";
            break;
        case 2:
            out << "The Data field contains an IPv4 address which is the Subject of this Query";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 140) {
        out << "ICMP Node Information Response (";
        switch (static_cast<int>(icmp_h->code)) {
        case 0:
            out << "A successful reply. The Reply Data field may or may not be empty";
            break;
        case 1:
            out << "The Responder refuses to supply the answer. The Reply Data field will be empty";
            break;
        case 2:
            out << "The Qtype of the Query is unknown to the Responder. The Reply Data field will be empty";
            break;
        default:
            out << "Unknown code";
            break;
        }
        out << ')';
    }
    else if (static_cast<int>(icmp_h->type) == 141 && static_cast<int>(icmp_h->code) == 0) {
        out << "Inverse Neighbor Discovery Solicitation Message";
    }
    else if (static_cast<int>(icmp_h->type) == 142 && static_cast<int>(icmp_h->code) == 0) {
        out << "Inverse Neighbor Discovery Advertisement Message";
    }
    else if (static_cast<int>(icmp_h->type) == 143) {
        out << "Multicast Listener Discovery (MLDv2) reports";
    }
    else if (static_cast<int>(icmp_h->type) == 144 && static_cast<int>(icmp_h->code) == 0) {
        out << "Home Agent Address Discovery Request Message";
    }
    else if (static_cast<int>(icmp_h->type) == 145 && static_cast<int>(icmp_h->code) == 0) {
        out << "Home Agent Address Discovery Reply Message";
    }
    else if (static_cast<int>(icmp_h->type) == 146 && static_cast<int>(icmp_h->code) == 0) {
        out << "Mobile Prefix Solicitation";
    }
    else if (static_cast<int>(icmp_h->type) == 147 && static_cast<int>(icmp_h->code) == 0) {
        out << "Mobile Prefix Advertisement";
    }
    else if (static_cast<int>(icmp_h->type) == 148) {
        out << "Certification Path Solicitation (SEND)";
    }
    else if (static_cast<int>(icmp_h->type) == 149) {
        out << "Certification Path Advertisement (SEND)";
    }
    else if (static_cast<int>(icmp_h->type) == 151) {
        out << "Multicast Router Advertisement (MRD)";
    }
    else if (static_cast<int>(icmp_h->type) == 152) {
        out << "Multicast Router Solicitation (MRD)";
    }
    else if (static_cast<int>(icmp_h->type) == 153) {
        out << "Multicast Router Termination (MRD)";
    }
    else if (static_cast<int>(icmp_h->type) == 155) {
        out << "RPL Control Message";
    }
    else {
        out << "unknown type";
    }
    out << std::endl;
}


int ipv6_loop(const uint8_t *pkt_data, uint32_t& prev_header_len) {
    ipv6_header* ipv6_h = (ipv6_header*)(pkt_data + prev_header_len);
    prev_header_len += 40;
    if (static_cast<int>(ipv6_h->next_header) == 6 || static_cast<int>(ipv6_h->next_header) == 17 || static_cast<int>(ipv6_h->next_header) == 58 || static_cast<int>(ipv6_h->next_header) == 59)
        return static_cast<int>(ipv6_h->next_header);
    ipv6_ext_header* ipv6_ext_h = (ipv6_ext_header*)(pkt_data + prev_header_len);
    prev_header_len += 8;
    while (static_cast<int>(ipv6_ext_h->next_header) != 6 && static_cast<int>(ipv6_ext_h->next_header) != 17 && static_cast<int>(ipv6_ext_h->next_header) != 58 && static_cast<int>(ipv6_ext_h->next_header) != 59) {
        prev_header_len += 8;
        ipv6_ext_h = (ipv6_ext_header*)(pkt_data + prev_header_len);
    }
    return static_cast<int>(ipv6_ext_h->next_header);
}

size_t packet_num = 0;

std::vector<std::string> pack_data(3);

void dispatcher_handler(u_char *dump, const struct pcap_pkthdr *header, const u_char *pkt_data) {
    //Unused variable
    (void)dump;
    std::ostringstream output;
    struct tm* ltime;
    char timestr[16];
    ethernet_header* eth_h;
    time_t local_tv_sec;
    /* convert the timestamp to readable format */
    local_tv_sec = header->ts.tv_sec;
    ltime = localtime(&local_tv_sec);
    strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
    ++packet_num;
    output << packet_num << ") Capture time is " << timestr << ',' << " length of the packet: " << header->len << std::endl;
    eth_h = (ethernet_header *)(pkt_data);
    output << "Ethernet, Scr: ";
    eth_h->scr.print_mac_addr(output);
    output << ", Dst: ";
    eth_h->dst.print_mac_addr(output);
    output << ", protocol: " << eth_h->protocol_type;
    //ipv4
    if (eth_h->protocol_type == 8) {
        ipv4_header* ip_h = (ipv4_header *)(pkt_data + 14); //length of ethernet header
        uint32_t ip_header_len = (ip_h->ver_ihl & 0xf) * 4;
        output << "\nInternet Protocol v. 4, ";
        ip_h->saddr.print_ip_addr(output);
        output << " -> ";
        ip_h->daddr.print_ip_addr(output);
        //udp
        if (static_cast<int>(ip_h->proto) == 17) {
            parce_udp(pkt_data, ip_header_len + 14, output);
        }
        //tcp
        else if (static_cast<int>(ip_h->proto) == 6) {
            parce_tcp(header, pkt_data, ip_header_len + 14, output);
        }
        //icmp
        else if (static_cast<int>(ip_h->proto) == 1) {
            parce_icmp(pkt_data, ip_header_len + 14, output);
        }
        //igmp
        else if (static_cast<int>(ip_h->proto) == 2) {
            parce_igmp(pkt_data, ip_header_len + 14, output);
        }
        else {
            output << "\nParcing is not supported now ;(\n";
        }
    }
    //ipv6
    else if (eth_h->protocol_type == 56710) {
        output << "\nInternet Protocol v. 6, ";
        ipv6_header* ipv6_h = (ipv6_header *)(pkt_data + 14); //length of ethernet header
        ipv6_h->src.print_ip_addr(output);
        output << " -> ";
        ipv6_h->dst.print_ip_addr(output);
        uint32_t len = 14;
        auto type_of_nextH = ipv6_loop(pkt_data, len);
        //tcp
        if (type_of_nextH == 6) {
            parce_tcp(header, pkt_data, len, output);
        }
        //udp
        else if (type_of_nextH == 17) {
            parce_udp(pkt_data, len, output);
        }
        //icmpv6
        else if (type_of_nextH == 58) {
            parce_icmpv6(pkt_data, len, output);
        }
        else {
            output << "Parcing is not supported now ;(";
        }
    }
    //arp
    else if (eth_h->protocol_type == 1544) {
        output << "\nAddress Resolution Protocol, ";
        arp_header* arp_h = (arp_header*)(pkt_data + 14);
        arp_h->operation = ntoh(arp_h->operation);
        arp_h->hard_type = ntoh(arp_h->hard_type);
        output << arp_h->operation << ' ';
        if (arp_h->hard_type != 1 || arp_h->proto != 8) {
            output << "\nParcing is not supported now ;(\n";
            return;
        }
        if (arp_h->operation == 1) {
            output << "(request)\nWho has ";
            arp_h->target_ip.print_ip_addr(output);
            output << "? Tell ";
            arp_h->sender_ip.print_ip_addr(output);
            output << std::endl;
        }
        else {
            output << "(reply)\n";
            arp_h->sender_ip.print_ip_addr(output);
            output << " is at ";
            arp_h->sender_mac.print_mac_addr(output);
            output << std::endl;
        }
    }
    else {
        output << "\nParcing is not supported now ;(\n";
    }
    output << std::endl;
    std::ostringstream hex_data;
    hex_data << packet_num << ") ";
    for (size_t i = 1; (i < header->caplen + 1); i++) {
        hex_data.unsetf(std::ios::dec);
        hex_data.setf(std::ios::hex);
        hex_data << std::setw(2) << std::setfill('0') << static_cast<int>(pkt_data[i - 1]);
        hex_data.unsetf(std::ios::hex);
        hex_data << ' ';
        if ((i % LINE_LEN) == 0)
            hex_data << std::endl;
    }
    hex_data << "\n\n";
    std::string complete_data = std::to_string(packet_num) + ") ";
    std::string data;
    data.resize(header->len);
    for (size_t i = 0; i < data.size(); i++) {
        if (pkt_data[i] > 32 && pkt_data[i] < 127)
            data[i] = pkt_data[i];
        else if (pkt_data[i] == 176)
            data[i] = ' ';
        else
            data[i] = static_cast<u_char>(176);
    }
    data += "\n\n";
    complete_data += data;
    pack_data[0]+=output.str();
    pack_data[1]+=hex_data.str();
    pack_data[2]+=complete_data;
}

void processing(const char* source, QMainWindow* main_w) {
    QObject::connect(&sniffer_emitter, SIGNAL(full_signal(std::string)), main_w, SLOT(accept_full(std::string)), Qt::QueuedConnection);
    QObject::connect(&sniffer_emitter, SIGNAL(hex_signal(std::string)), main_w, SLOT(accept_hex(std::string)), Qt::QueuedConnection);
    QObject::connect(&sniffer_emitter, SIGNAL(ascii_signal(std::string)), main_w, SLOT(accept_ascii(std::string)), Qt::QueuedConnection);
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    /* Open the capture file */
    if ((handle = pcap_open_offline(source,			 // name of the device
        errbuf			                             // error buffer
    )) == nullptr) {
        std::cerr << "\nUnable to open the file " << source << '\n';
        return;
    }
    // read and dispatch packets until EOF is reached
    pcap_loop(handle, 0, dispatcher_handler, nullptr);
    sniffer_emitter.emit_full(pack_data[0]);
    sniffer_emitter.emit_hex(pack_data[1]);
    sniffer_emitter.emit_ascii(pack_data[2]);
    for(size_t i = 0; i < 3; i++){
        pack_data[i].clear();
    }
    packet_num = 0;
}
