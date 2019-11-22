#define _CRT_SECURE_NO_WARNINGS

#include "pcap.h"
#include <time.h>
#include <iostream>
#include <string>
#include <iomanip>

#define LINE_LEN 16

size_t packet_num = 0;

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	//Unused variable
	(void)temp1;

	struct tm* ltime;
	char timestr[16];
	time_t local_tv_sec;
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
	std::cout << ++packet_num << ") Capture time is " << timestr << ',' << " length of the packet: " << header->len << std::endl;

	/* Print the packet */
	std::cout << "All data in hex:\n";
	for (size_t i = 1; (i < header->caplen + 1); i++) {
		std::cout.unsetf(std::ios::dec);
		std::cout.setf(std::ios::hex);
		std::cout << std::setw(2) << std::setfill('0') << static_cast<int>(pkt_data[i - 1]);
		std::cout.unsetf(std::ios::hex);
		std::cout << ' ';
		if ((i % LINE_LEN) == 0)
			std::cout << std::endl;
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

int main_f() {
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[] = "../dumps/ip_and_arp_dump.txt";

	/* Open the capture file */
	if ((fp = pcap_open_offline(source,			 // name of the device
		errbuf			 // error buffer
	)) == NULL) {
		std::cerr << "\nUnable to open the file " << source << '\n';
		return -1;
	}

	// read and dispatch packets until EOF is reached
	pcap_loop(fp, 0, dispatcher_handler, NULL);

	return 0;
}
