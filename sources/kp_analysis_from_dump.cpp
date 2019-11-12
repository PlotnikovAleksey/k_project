#include <stdio.h>
#include <pcap.h>
#include <time.h>
#include <iostream>
#include <string>
#include <iomanip>

#define LINE_LEN 16

size_t packet_num = 0;

void dispatcher_handler(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	//Unused variable
	(void)temp1;

	struct tm ltime;
	char timestr[16];
	time_t local_tv_sec;
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);
	std::cout << ++packet_num << ") Capture time is " << timestr << ',' << " length of the packet: " << header->len << std::endl;

	/* Print the packet */
	std::cout << "All data in hex:\n";
	for (size_t i = 1; (i < header->caplen + 1); i++) {
		std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(pkt_data[i - 1]);
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

int main() {
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	char source[PCAP_BUF_SIZE];

	/* Create the source string according to the new Npcap syntax */
	if (pcap_createsrcstr(source,			                        // variable that will keep the source string
		PCAP_SRC_FILE,	                                            // we want to open a file
		NULL,			                                            // remote host
		NULL,			                                            // port on the remote host
		"../dumps/ip_and_arp_dump.txt",		// name of the file we want to open
		errbuf			                                            // error buffer
	) != 0) {
		std::cerr << "\nError creating a source string\n";
		return -1;
	}

	/* Open the capture file */
	if ((fp = pcap_open(source,			 // name of the device
		65536,			                 // portion of the packet to capture
						                 // 65536 guarantees that the whole packet will be captured on all the link layers
		PCAP_OPENFLAG_PROMISCUOUS, 	     // promiscuous mode
		1000,				             // read timeout
		NULL,				             // authentication on the remote machine
		errbuf			                 // error buffer
	)) == NULL) {
		std::cerr << "\nUnable to open the file " << source << '\n';
		return -1;
	}

	// read and dispatch packets until EOF is reached
	pcap_loop(fp, 0, dispatcher_handler, NULL);

	return 0;
}
