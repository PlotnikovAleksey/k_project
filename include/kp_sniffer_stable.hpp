// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#ifndef INCLUDE_SNIFFER_HPP_
#define INCLUDE_SNIFFER_HPP_

#define _CRT_SECURE_NO_WARNINGS

#include <pcap.h>
#include <stdint.h>
#include <time.h>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#define HAVE_REMOTE

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(uint8_t* dump, const struct pcap_pkthdr* header,
                    const uint8_t* pkt_data);

int filter_on(pcap_if_t* device, pcap_t* handle, char* filter);

int sniffing(char* user_filter, uint32_t packet_num);

#endif  // INCLUDE_SNIFFER_HPP_
