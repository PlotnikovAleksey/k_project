// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#include <kp_analysis_from_dump.hpp>

uint16_t ntoh(uint16_t aim) {
  uint16_t first = 0, second = 0;
  first = static_cast<uint16_t>(65280) & aim;
  second = static_cast<uint16_t>(255) & aim;
  first >>= 8;
  second <<= 8;
  return first | second;
}

void mac_address::print_mac_addr() {
  std::cout.unsetf(std::ios::dec);
  std::cout.setf(std::ios::hex);
  std::cout << '(' << static_cast<int>(byte1) << ':' << static_cast<int>(byte2)
            << ':' << static_cast<int>(byte3) << ':' << static_cast<int>(byte4)
            << ':' << static_cast<int>(byte5) << ':' << static_cast<int>(byte6)
            << ')';
  std::cout.unsetf(std::ios::hex);
}

void ipv4_address::print_ip_addr() {
  std::cout << static_cast<int>(byte1) << '.' << static_cast<int>(byte2) << '.'
            << static_cast<int>(byte3) << '.' << static_cast<int>(byte4);
}

void ipv6_address::print_ip_addr() {
  size_t longest_count = 0;
  size_t longest_begin = 322;
  bool found = find_longest_zeros(longest_count, longest_begin);
  if (!found) {
    std::cout.unsetf(std::ios::dec);
    std::cout.setf(std::ios::hex);
    for (size_t i = 0; i < 16; i++) {
      std::cout << std::setw(2) << std::setfill('0')
                << static_cast<int>(bytes[i]);
      if (i % 2 == 1 && i != 15) std::cout << ':';
    }
    std::cout.unsetf(std::ios::hex);
  } else {
    std::cout.unsetf(std::ios::dec);
    std::cout.setf(std::ios::hex);
    for (size_t i = 0; i < 16; i++) {
      if (i == longest_begin) {
        if (longest_begin == 0)
          std::cout << "::";
        else
          std::cout << ':';
        i += 2 * longest_count - 1;
      } else {
        std::cout << std::setw(2) << std::setfill('0')
                  << static_cast<int>(bytes[i]);
        if (i % 2 == 1 && i != 15) std::cout << ':';
      }
    }
    std::cout.unsetf(std::ios::hex);
  }
}

bool ipv6_address::find_longest_zeros(size_t &longest_count,
                                      size_t &longest_begin) {
  size_t cur_count = 0;
  size_t cur_begin = 322;
  for (size_t i = 0; i < 16; i += 2) {
    if (bytes[i] + bytes[i + 1] == 0) {
      if (cur_begin != 322) {
        cur_count++;
      } else if (cur_begin == 322) {
        cur_begin = i;
        cur_count++;
      }
      if (cur_count > longest_count) {
        longest_count = cur_count;
        longest_begin = cur_begin;
      }
    } else {
      cur_count = 0;
      cur_begin = 322;
    }
  }
  if (longest_begin == 322 || longest_count == 1)
    return false;
  else
    return true;
}

void parce_udp(const uint8_t *pkt_data, uint32_t prev_header_len) {
  uint16_t sport, dport, len;
  udp_header *udp_h = (udp_header *)((uint8_t *)pkt_data + prev_header_len);
  sport = ntoh(udp_h->sport);
  dport = ntoh(udp_h->dport);
  len = ntoh(udp_h->len);
  std::cout << "\nUser Datagram Protocol, Scr port: " << sport
            << ", Dst port: " << dport << ", Len: " << len << "\n";
}

void parce_tcp(const struct pcap_pkthdr *header, const uint8_t *pkt_data,
               uint32_t prev_header_len) {
  uint16_t sport, dport;
  tcp_header *tcp_h = (tcp_header *)((uint8_t *)pkt_data + prev_header_len);
  sport = ntoh(tcp_h->sport);
  dport = ntoh(tcp_h->dport);
  uint16_t different_info = ntoh(tcp_h->different_info);
  uint16_t window_size = ntoh(tcp_h->window_size);
  uint16_t tcp_header_len = (different_info >> 12) * 4;
  uint16_t tcp_payload_len = header->len - prev_header_len - tcp_header_len;
  std::cout << "\nTransmission Control Protocol, Scr port: " << sport
            << ", Dst port: " << dport << ", Win: " << window_size
            << ", Payload len: " << tcp_payload_len << "\n";
}

void parce_igmp(const uint8_t *pkt_data, uint32_t prev_header_len) {
  igmp_header *igmp_h = (igmp_header *)((uint8_t *)pkt_data + prev_header_len);
  std::cout << "\nInternet Group Management Protocol";
  if (igmp_h->type == 0x11) {
    std::cout << "\nMembership query, ";
  } else if (igmp_h->type == 0x16 || igmp_h->type == 0x17) {
    std::cout << " version 2\n";
    if (igmp_h->type == 0x16)
      std::cout << "Membership report, ";
    else
      std::cout << "Leave Group, ";
  } else if (igmp_h->type == 0x22) {
    std::cout << " version 3\nMembership Report, ";
  } else {
    std::cout << " unknown version\n";
  }
  std::cout << "multicast address: ";
  igmp_h->group_address.print_ip_addr();
  std::cout << std::endl;
}

void parce_icmp(const uint8_t *pkt_data, uint32_t prev_header_len) {
  icmp_header *icmp_h = (icmp_header *)((uint8_t *)pkt_data + prev_header_len);
  std::cout << "\nInternet Control Message Protocol, ";
  if (static_cast<int>(icmp_h->type) == 0 &&
      static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Echo Reply";
  } else if (static_cast<int>(icmp_h->type) == 3) {
    std::cout << "Destination Unreachable (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "Destination network unreachable";
        break;
      case 1:
        std::cout << "Destination host unreachable";
        break;
      case 2:
        std::cout << "Destination protocol unreachable";
        break;
      case 3:
        std::cout << "Destination port unreachable";
        break;
      case 4:
        std::cout << "Fragmentation required";
        break;
      case 5:
        std::cout << "Source route failed";
        break;
      case 6:
        std::cout << "Destination network unknown";
        break;
      case 7:
        std::cout << "Destination host unknown";
        break;
      case 8:
        std::cout << "Source host isolated";
        break;
      case 9:
        std::cout << "Network administratively prohibited";
        break;
      case 10:
        std::cout << "Host administratively prohibited";
        break;
      case 11:
        std::cout << "Network unreachable for ToS";
        break;
      case 12:
        std::cout << "Host unreachable for ToS";
        break;
      case 13:
        std::cout << "Communication administratively prohibited";
        break;
      case 14:
        std::cout << "Host Precedence Violation";
        break;
      case 15:
        std::cout << "Precedence cutoff in effect";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 5) {
    std::cout << "Redirect Message (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "Redirect Datagram for the Network";
        break;
      case 1:
        std::cout << "Redirect Datagram for the Host";
        break;
      case 2:
        std::cout << "Redirect Datagram for the ToS & network";
        break;
      case 3:
        std::cout << "Redirect Datagram for the ToS & host";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 8 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Echo Request";
  } else if (static_cast<int>(icmp_h->type) == 9 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Router Advertisement";
  } else if (static_cast<int>(icmp_h->type) == 10 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Router Solicitation";
  } else if (static_cast<int>(icmp_h->type) == 11) {
    std::cout << "Time Exceeded (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "TTL expired in transit";
        break;
      case 1:
        std::cout << "Fragment reassembly time exceeded";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 11) {
    std::cout << "Parameter Problem: Bad IP header (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "Pointer indicates the error";
        break;
      case 1:
        std::cout << "Missing a required option";
        break;
      case 2:
        std::cout << "Bad length";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 13 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Timestamp";
  } else if (static_cast<int>(icmp_h->type) == 14 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Timestamp Reply";
  } else if (static_cast<int>(icmp_h->type) == 40) {
    std::cout << "Photuris, Security failures";
  } else if (static_cast<int>(icmp_h->type) == 42 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Extended Echo Request";
  } else if (static_cast<int>(icmp_h->type) == 43) {
    std::cout << "Extended Echo Reply (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "No Error";
        break;
      case 1:
        std::cout << "Malformed Query";
        break;
      case 2:
        std::cout << "No Such Interface";
        break;
      case 3:
        std::cout << "No Such Table Entry";
        break;
      case 4:
        std::cout << "Multiple Interfaces Satisfy Query";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else {
    std::cout << "unknown type";
  }
  std::cout << std::endl;
}

void parce_icmpv6(const uint8_t *pkt_data, uint32_t prev_header_len) {
  icmp_header *icmp_h = (icmp_header *)((uint8_t *)pkt_data + prev_header_len);
  std::cout << "\nInternet Control Message Protocol v6, ";
  if (static_cast<int>(icmp_h->type) == 1) {
    std::cout << "Destination unreachable (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "no route to destination";
        break;
      case 1:
        std::cout
            << "communication with destination administratively prohibited";
        break;
      case 2:
        std::cout << "beyond scope of source address";
        break;
      case 3:
        std::cout << "address unreachable";
        break;
      case 4:
        std::cout << "port unreachable";
        break;
      case 5:
        std::cout << "source address failed ingress/egress policy";
        break;
      case 6:
        std::cout << "reject route to destination";
        break;
      case 7:
        std::cout << "Error in Source Routing Header";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 2 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Packet Too Big";
  } else if (static_cast<int>(icmp_h->type) == 3) {
    std::cout << "Time exceeded (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "hop limit exceeded in transit";
        break;
      case 1:
        std::cout << "fragment reassembly time exceeded";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 4) {
    std::cout << "Parameter problem (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "erroneous header field encountered";
        break;
      case 1:
        std::cout << "unrecognized Next Header type encountered";
        break;
      case 2:
        std::cout << "unrecognized IPv6 option encountered";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 128 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Echo Request";
  } else if (static_cast<int>(icmp_h->type) == 129 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Echo Reply";
  } else if (static_cast<int>(icmp_h->type) == 130 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Multicast Listener Query";
  } else if (static_cast<int>(icmp_h->type) == 131 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Multicast Listener Report";
  } else if (static_cast<int>(icmp_h->type) == 132 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Multicast Listener Done";
  } else if (static_cast<int>(icmp_h->type) == 133 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Router Solicitation";
  } else if (static_cast<int>(icmp_h->type) == 134 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Router Advertisement";
  } else if (static_cast<int>(icmp_h->type) == 135 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Neighbor Solicitation";
  } else if (static_cast<int>(icmp_h->type) == 136 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Neighbor Advertisement";
  } else if (static_cast<int>(icmp_h->type) == 137 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Redirect Message";
  } else if (static_cast<int>(icmp_h->type) == 138) {
    std::cout << "Router Renumbering (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "Router Renumbering Command";
        break;
      case 1:
        std::cout << "Router Renumbering Result";
        break;
      case 255:
        std::cout << "Sequence Number Reset";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 139) {
    std::cout << "ICMP Node Information Query (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "The Data field contains an IPv6 address which is the "
                     "Subject of this Query";
        break;
      case 1:
        std::cout << "The Data field contains a name which is the Subject of "
                     "this Query, or is empty, as in the case of a NOOP";
        break;
      case 2:
        std::cout << "The Data field contains an IPv4 address which is the "
                     "Subject of this Query";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 140) {
    std::cout << "ICMP Node Information Response (";
    switch (static_cast<int>(icmp_h->code)) {
      case 0:
        std::cout << "A successful reply. The Reply Data field may or may not "
                     "be empty";
        break;
      case 1:
        std::cout << "The Responder refuses to supply the answer. The Reply "
                     "Data field will be empty";
        break;
      case 2:
        std::cout << "The Qtype of the Query is unknown to the Responder. The "
                     "Reply Data field will be empty";
        break;
      default:
        std::cout << "Unknown code";
        break;
    }
    std::cout << ')';
  } else if (static_cast<int>(icmp_h->type) == 141 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Inverse Neighbor Discovery Solicitation Message";
  } else if (static_cast<int>(icmp_h->type) == 142 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Inverse Neighbor Discovery Advertisement Message";
  } else if (static_cast<int>(icmp_h->type) == 143) {
    std::cout << "Multicast Listener Discovery (MLDv2) reports";
  } else if (static_cast<int>(icmp_h->type) == 144 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Home Agent Address Discovery Request Message";
  } else if (static_cast<int>(icmp_h->type) == 145 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Home Agent Address Discovery Reply Message";
  } else if (static_cast<int>(icmp_h->type) == 146 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Mobile Prefix Solicitation";
  } else if (static_cast<int>(icmp_h->type) == 147 &&
             static_cast<int>(icmp_h->code) == 0) {
    std::cout << "Mobile Prefix Advertisement";
  } else if (static_cast<int>(icmp_h->type) == 148) {
    std::cout << "Certification Path Solicitation (SEND)";
  } else if (static_cast<int>(icmp_h->type) == 149) {
    std::cout << "Certification Path Advertisement (SEND)";
  } else if (static_cast<int>(icmp_h->type) == 151) {
    std::cout << "Multicast Router Advertisement (MRD)";
  } else if (static_cast<int>(icmp_h->type) == 152) {
    std::cout << "Multicast Router Solicitation (MRD)";
  } else if (static_cast<int>(icmp_h->type) == 153) {
    std::cout << "Multicast Router Termination (MRD)";
  } else if (static_cast<int>(icmp_h->type) == 155) {
    std::cout << "RPL Control Message";
  } else {
    std::cout << "unknown type";
  }
  std::cout << std::endl;
}

int ipv6_loop(const uint8_t *pkt_data, uint32_t &prev_header_len) {
  ipv6_header *ipv6_h = (ipv6_header *)(pkt_data + prev_header_len);
  prev_header_len += 40;
  if (static_cast<int>(ipv6_h->next_header) == 6 ||
      static_cast<int>(ipv6_h->next_header) == 17 ||
      static_cast<int>(ipv6_h->next_header) == 58 ||
      static_cast<int>(ipv6_h->next_header) == 59)
    return static_cast<int>(ipv6_h->next_header);
  ipv6_ext_header *ipv6_ext_h = (ipv6_ext_header *)(pkt_data + prev_header_len);
  prev_header_len += 8;
  while (static_cast<int>(ipv6_ext_h->next_header) != 6 &&
         static_cast<int>(ipv6_ext_h->next_header) != 17 &&
         static_cast<int>(ipv6_ext_h->next_header) != 58 &&
         static_cast<int>(ipv6_ext_h->next_header) != 59) {
    std::cout << std::endl << static_cast<int>(ipv6_ext_h->next_header);
    prev_header_len += 8;
    ipv6_ext_h = (ipv6_ext_header *)(pkt_data + prev_header_len);
  }
  return static_cast<int>(ipv6_ext_h->next_header);
}

size_t packet_num = 0;

void dispatcher_handler(u_char *dump, const struct pcap_pkthdr *header,
                        const u_char *pkt_data) {
  // Unused variable
  (void)dump;

  struct tm *ltime;
  char timestr[16];
  ethernet_header *eth_h;
  time_t local_tv_sec;
  /* convert the timestamp to readable format */
  local_tv_sec = header->ts.tv_sec;
  ltime = localtime(&local_tv_sec);
  strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
  std::cout << ++packet_num << ") Capture time is " << timestr << ','
            << " length of the packet: " << header->len << std::endl;
  eth_h = (ethernet_header *)(pkt_data);
  std::cout << "Ethernet, Scr: ";
  eth_h->scr.print_mac_addr();
  std::cout << ", Dst: ";
  eth_h->dst.print_mac_addr();
  std::cout << ", protocol: " << eth_h->protocol_type;
  // ipv4
  if (eth_h->protocol_type == 8) {
    ipv4_header *ip_h =
        (ipv4_header *)(pkt_data + 14);  // length of ethernet header
    uint32_t ip_header_len = (ip_h->ver_ihl & 0xf) * 4;
    std::cout << "\nInternet Protocol v. 4, ";
    ip_h->saddr.print_ip_addr();
    std::cout << " -> ";
    ip_h->daddr.print_ip_addr();
    // udp
    if (static_cast<int>(ip_h->proto) == 17) {
      parce_udp(pkt_data, ip_header_len + 14);
    }
    // tcp
    else if (static_cast<int>(ip_h->proto) == 6) {
      parce_tcp(header, pkt_data, ip_header_len + 14);
    }
    // icmp
    else if (static_cast<int>(ip_h->proto) == 1) {
      parce_icmp(pkt_data, ip_header_len + 14);
    }
    // igmp
    else if (static_cast<int>(ip_h->proto) == 2) {
      parce_igmp(pkt_data, ip_header_len + 14);
    } else {
      std::cout << "\nParcing is not supported now ;(\n";
    }
  }
  // ipv6
  else if (eth_h->protocol_type == 56710) {
    std::cout << "\nInternet Protocol v. 6, ";
    ipv6_header *ipv6_h =
        (ipv6_header *)(pkt_data + 14);  // length of ethernet header
    ipv6_h->src.print_ip_addr();
    std::cout << " -> ";
    ipv6_h->dst.print_ip_addr();
    uint32_t len = 14;
    auto type_of_nextH = ipv6_loop(pkt_data, len);
    // tcp
    if (type_of_nextH == 6) {
      parce_tcp(header, pkt_data, len);
    }
    // udp
    else if (type_of_nextH == 17) {
      parce_udp(pkt_data, len);
    }
    // icmpv6
    else if (type_of_nextH == 58) {
      parce_icmpv6(pkt_data, len);
    } else {
      std::cout << "Parcing is not supported now ;(";
    }
  }
  // arp
  else if (eth_h->protocol_type == 1544) {
    std::cout << "\nAddress Resolution Protocol, ";
    arp_header *arp_h = (arp_header *)(pkt_data + 14);
    arp_h->operation = ntoh(arp_h->operation);
    arp_h->hard_type = ntoh(arp_h->hard_type);
    std::cout << arp_h->operation << ' ';
    if (arp_h->hard_type != 1 || arp_h->proto != 8) {
      std::cout << "\nParcing is not supported now ;(\n";
      return;
    }
    if (arp_h->operation == 1) {
      std::cout << "(request)\nWho has ";
      arp_h->target_ip.print_ip_addr();
      std::cout << "? Tell ";
      arp_h->sender_ip.print_ip_addr();
      std::cout << std::endl;
    } else {
      std::cout << "(reply)\n";
      arp_h->sender_ip.print_ip_addr();
      std::cout << " is at ";
      arp_h->sender_mac.print_mac_addr();
      std::cout << std::endl;
    }
  } else {
    std::cout << "\nParcing is not supported now ;(\n";
  }
  std::cout << std::endl;

  std::cout << "All data in hex:\n";
  for (size_t i = 1; (i < header->caplen + 1); i++) {
    std::cout.unsetf(std::ios::dec);
    std::cout.setf(std::ios::hex);
    std::cout << std::setw(2) << std::setfill('0')
              << static_cast<int>(pkt_data[i - 1]);
    std::cout.unsetf(std::ios::hex);
    std::cout << ' ';
    if ((i % LINE_LEN) == 0) std::cout << std::endl;
  }

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
  std::cout << "\n\nAll data in ascii:\n" << data << "\n\n";
}

void processing(const char *source) {
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  /* Open the capture file */
  if ((handle = pcap_open_offline(source,  // name of the device
                                  errbuf   // error buffer
                                  )) == NULL) {
    std::cerr << "\nUnable to open the file " << source << '\n';
    return;
  }
  // read and dispatch packets until EOF is reached
  pcap_loop(handle, 0, dispatcher_handler, NULL);
  packet_num = 0;
}
