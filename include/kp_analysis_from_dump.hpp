// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#ifndef INCLUDE_ANALYSIS_HPP_
#define INCLUDE_ANALYSIS_HPP_

#define _CRT_SECURE_NO_WARNINGS

#include <stdint.h>
#include <time.h>
#include <iomanip>
#include <iostream>
#include <string>
#include <sstream>
#include "pcap.h"

#define LINE_LEN 16

// Network to host byte order
uint16_t ntoh(uint16_t aim);

/* 6 bytes MAC address */
class mac_address {
 public:
  uint8_t byte1;
  uint8_t byte2;
  uint8_t byte3;
  uint8_t byte4;
  uint8_t byte5;
  uint8_t byte6;

  void print_mac_addr();
};

/* Ethernet header */
class ethernet_header {
 public:
  mac_address dst;         // Source address
  mac_address scr;         // Destination address
  uint16_t protocol_type;  // Type of protocol
};

/* 4 bytes IP address */
class ipv4_address {
 public:
  uint8_t byte1;
  uint8_t byte2;
  uint8_t byte3;
  uint8_t byte4;

  void print_ip_addr();
};

/* IPv4 header */
class ipv4_header {
 public:
  uint8_t ver_ihl;  // Version (4 bits) + Internet header length (4 bits)
  uint8_t tos;      // Type of service
  uint16_t tlen;    // Total length
  uint16_t identification;  // Identification
  uint16_t flags_fo;        // Flags (3 bits) + Fragment offset (13 bits)
  uint8_t ttl;              // Time to live
  uint8_t proto;            // Protocol
  uint16_t crc;             // Header checksum
  ipv4_address saddr;       // Source address
  ipv4_address daddr;       // Destination address
  uint32_t op_pad;          // Option + Padding
};

/* ARP header */
class arp_header {
 public:
  uint16_t hard_type;      // Hardware type
  uint16_t proto;          // Protocol type
  uint8_t hard_len;        // Hardware length
  uint8_t proto_len;       // Protocol length
  uint16_t operation;      // Operation
  mac_address sender_mac;  // Sender hardware address
  ipv4_address sender_ip;  // Sender protocol address
  mac_address target_mac;  // Target hardware address
  ipv4_address target_ip;  // Target protocol address
};

/* UDP header*/
class udp_header {
 public:
  uint16_t sport;  // Source port
  uint16_t dport;  // Destination port
  uint16_t len;    // Datagram length
  uint16_t crc;    // Checksum
};

/* TCP header*/
class tcp_header {
 public:
  uint16_t sport;                  // Source port
  uint16_t dport;                  // Destination port
  uint32_t seq_number;             // Порядковый номер
  uint32_t acknowledgment_number;  // Номер подтверждения
  uint16_t different_info;  // 0 - 3 Длина заголовка, 4 - 9 Зарезервировано, 10
                            // - 15 Флаги
  uint16_t window_size;  // Размер Окна
  uint16_t crc;          // Checksum
  uint16_t urgent_ptr;   // Указатель важности
};

/* IGMP header*/
class igmp_header {
 public:
  uint8_t type;                // Тип
  uint8_t max_resp_code;       // Код макс. ответа
  uint16_t crc;                // Контрольная сумма
  ipv4_address group_address;  // Групповой адрес
};

/* ICMP header*/
class icmp_header {
 public:
  uint8_t type;  // Тип
  uint8_t code;  // Код
  uint16_t crc;  // Контрольная сумма
};

/* 16 bytes IP address */
class ipv6_address {
 public:
  uint8_t bytes[16];

  void print_ip_addr();

 private:
  bool find_longest_zeros(size_t &longest_count, size_t &longest_begin);
};

/* IPv6 header*/
class ipv6_header {
 public:
  uint32_t diff_info;    // Version, Traffic Class, Flow Label
  uint16_t payload_len;  // Payload Length
  uint8_t next_header;   // Next Header
  uint8_t hop_limit;     // Hop Limit
  ipv6_address src;      // Source Address
  ipv6_address dst;      // Destination Address
};

/* IPv6 extension header*/
class ipv6_ext_header {
 public:
  uint8_t next_header;  // Next Header
  uint8_t ext_len;      // Hdr Ext Len
  uint16_t rout_seg;    // Routing Type, Segments Left
  uint32_t data;        // Varies from type of header
};

void parce_udp(const uint8_t *pkt_data, uint32_t prev_header_len);

void parce_tcp(const struct pcap_pkthdr *header, const uint8_t *pkt_data,
               uint32_t prev_header_len);

void parce_igmp(const uint8_t *pkt_data, uint32_t prev_header_len);

void parce_icmp(const uint8_t *pkt_data, uint32_t prev_header_len);

void parce_icmpv6(const uint8_t *pkt_data, uint32_t prev_header_len);

int ipv6_loop(const uint8_t *pkt_data, uint32_t &prev_header_len);

void dispatcher_handler(u_char *dump, const struct pcap_pkthdr *header,
                        const u_char *pkt_data);

void processing(const char *source);

#endif  // INCLUDE_ANALYSIS_HPP_
