#include <gtest/gtest.h>
#include <kp_analysis_from_dump.hpp>

TEST(Sniffer, ARP) { processing("dumps/arp_dump.txt"); }

TEST(Sniffer, TCP) { processing("dumps/tcp_dump.txt"); }

TEST(Sniffer, particular_TCP_port) { processing("dumps/port443_dump.txt"); }

TEST(Sniffer, UDP) { processing("dumps/udp_dump.txt"); }

TEST(Sniffer, ICMP) { processing("dumps/icmp_dump.txt"); }

TEST(Sniffer, IGMP) { processing("dumps/igmp_dump.txt"); }

TEST(Sniffer, IPv6) { processing("dumps/ipv6_dump.txt"); }
