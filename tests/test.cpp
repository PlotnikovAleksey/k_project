// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#include <gtest/gtest.h>
#include <kp_analysis_from_dump.hpp>

TEST(Sniffer, ARP) { processing("dumps/arp_dump.ydp"); }

TEST(Sniffer, TCP) { processing("dumps/tcp_dump.ydp"); }

TEST(Sniffer, particular_TCP_port) { processing("dumps/port443_dump.ydp"); }

TEST(Sniffer, UDP) { processing("dumps/udp_dump.ydp"); }

TEST(Sniffer, ICMP) { processing("dumps/icmp_dump.ydp"); }

TEST(Sniffer, IGMP) { processing("dumps/igmp_dump.ydp"); }

TEST(Sniffer, IPv6) { processing("dumps/ipv6_dump.ydp"); }
