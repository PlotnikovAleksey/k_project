#include <iostream>
#include <iomanip>
#include <pcap.h>
#include <Winsock2.h>
#include <tchar.h>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <time.h>
#define HAVE_REMOTE
//#include <Ws2tcpip.h>
//#include <WS2tcpip.h>
#pragma comment (lib,"Ws2_32.lib")

BOOL LoadNpcapDlls() {
	_TCHAR npcap_dir[512];
	UINT len;
	len = GetSystemDirectory(npcap_dir, 480);
	if (!len) {
		std::cerr << "Error in GetSystemDirectory: " << GetLastError();
		return FALSE;
	}
	_tcscat_s(npcap_dir, 512, _T("\\Npcap"));
	if (SetDllDirectory(npcap_dir) == 0) {
		std::cerr << "Error in SetDllDirectory: " << GetLastError();
		return FALSE;
	}
	return TRUE;
}

/* 6 bytes MAC address */
class mac_address {
public:
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;

	void print_mac_addr() {
		std::cout.unsetf(std::ios::dec);
		std::cout.setf(std::ios::hex);
		std::cout << '(' << static_cast<int>(byte1) << ':' << static_cast<int>(byte2) << ':' << static_cast<int>(byte3) << ':' << static_cast<int>(byte4) << ':' << static_cast<int>(byte5) << ':' << static_cast<int>(byte6) << ')';
		std::cout.unsetf(std::ios::hex);
	}
};

class ethernet_header {
public:
	mac_address dst;
	mac_address scr;
	u_short protocol_type;
};

/* 4 bytes IP address */
class ipv4_address {
public:
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;

	void print_ip_addr() {
		std::cout << static_cast<int>(byte1) << '.' << static_cast<int>(byte2) <<
			'.' << static_cast<int>(byte3) << '.' << static_cast<int>(byte4);
	}
};

/* IPv4 header */
class ipv4_header {
public:
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ipv4_address saddr;		// Source address
	ipv4_address daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
};

/* ARP header */
class arp_header {
public:
	u_short	hard_type;		  // Hardware type
	u_short proto;			  // Protocol type 
	u_char hard_len;          // Hardware length
	u_char proto_len;         // Protocol length
	u_short operation;        // Operation
	mac_address sender_mac;   // Sender hardware address
	ipv4_address sender_ip;   // Sender protocol address
	mac_address target_mac;   // Target hardware address
	ipv4_address target_ip;   // Target protocol address
};

/* UDP header*/
class udp_header {
public:
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
};

/* TCP header*/
class tcp_header {
public:
	u_short sport;			        // Source port
	u_short dport;			        // Destination port
	u_int seq_number;               // Порядковый номер
	u_int acknowledgment_number;    // Номер подтверждения
	u_short different_info;         // 0 - 3 Длина заголовка, 4 - 9 Зарезервировано, 10 - 15 Флаги
	u_short window_size;            // Размер Окна
	u_short crc;			        // Checksum
	u_short urgent_ptr;             // Указатель важности
};

void parce_udp(const struct pcap_pkthdr *header, const u_char *pkt_data, u_int prev_header_len) {
	u_short sport, dport, len;
	udp_header* udp_h;
	udp_h = (udp_header *)((u_char*)pkt_data + 14 + prev_header_len);
	sport = ntohs(udp_h->sport);
	dport = ntohs(udp_h->dport);
	len = ntohs(udp_h->len);
	std::cout << "\nUser Datagram Protocol, Scr port: " << sport << ", Dst port: " << dport << ", Len: " << len << "\n";
}

void parce_tcp(const struct pcap_pkthdr *header, const u_char *pkt_data, u_int prev_header_len) {
	u_short sport, dport;
	tcp_header* tcp_h;
	tcp_h = (tcp_header *)((u_char*)pkt_data + 14 + prev_header_len);
	sport = ntohs(tcp_h->sport);
	dport = ntohs(tcp_h->dport);
	u_short different_info = ntohs(tcp_h->different_info);
	u_short window_size = ntohs(tcp_h->window_size);
	u_short tcp_header_len = (different_info >> 12) * 4;
	u_short tcp_payload_len = header->len - 14 - prev_header_len - tcp_header_len;
	std::cout << "\nTransmission Control Protocol, Scr port: " << sport << ", Dst port: " << dport << ", Win: " << window_size << ", Payload len: " << tcp_payload_len << "\n";
}

size_t packet_num = 0;

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *dump, const struct pcap_pkthdr *header, const u_char *pkt_data) {
	struct tm ltime;
	char timestr[16];
	ethernet_header* eth_h;
	time_t local_tv_sec;
    pcap_dump(dump, header, pkt_data);
	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	localtime_s(&ltime, &local_tv_sec);
	strftime(timestr, sizeof(timestr), "%H:%M:%S", &ltime);
	std::cout << ++packet_num << ") Capture time is " << timestr << ',' << " length of the packet: " << header->len << std::endl;

	eth_h = (ethernet_header *)(pkt_data);
	std::cout << "Ethernet, Scr: ";
	eth_h->scr.print_mac_addr();
	std::cout << ", Dst: ";
	eth_h->dst.print_mac_addr();
	std::cout << ", protocol: " << eth_h->protocol_type;
	//ipv4
	if (eth_h->protocol_type == 8) {
		ipv4_header* ip_h = (ipv4_header *)(pkt_data + 14); //length of ethernet header
		u_int ip_header_len = (ip_h->ver_ihl & 0xf) * 4;
		std::cout << "\nInternet Protocol v. 4, ";
		ip_h->saddr.print_ip_addr();
		std::cout << " -> ";
		ip_h->daddr.print_ip_addr();
		//udp
		if (static_cast<int>(ip_h->proto) == 17) {
			parce_udp(header, pkt_data, ip_header_len);
		}
		//tcp
		else if (static_cast<int>(ip_h->proto) == 6) {
			parce_tcp(header, pkt_data, ip_header_len);
		}
		//icmp
		else if (static_cast<int>(ip_h->proto) == 1) {
			std::cout << "\nicmp\n";
		}
		//igmp
		else if (static_cast<int>(ip_h->proto) == 2) {
			std::cout << "\nigmp\n";
		}
		else {
			std::cout << "\nParcing is not supported now ;(\n";
		}
	}
	//ipv6
	else if (eth_h->protocol_type == 56710) {
		std::cout << "\nipv6\n";
	}
	//arp
	else if (eth_h->protocol_type == 1544) {
		std::cout << "\nAddress Resolution Protocol, ";
		arp_header* arp_h = (arp_header*)(pkt_data + 14);
		arp_h->operation = ntohs(arp_h->operation);
		arp_h->hard_type = ntohs(arp_h->hard_type);
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
		}
		else {
			std::cout << "(reply)\n";
			arp_h->sender_ip.print_ip_addr();
			std::cout << " is at ";
			arp_h->sender_mac.print_mac_addr();
			std::cout << std::endl;
		}
	}
	else {
		std::cout << "\nParcing is not supported now ;(\n";
	}
	//icmp
	std::cout << std::endl;
}

int filter_on(pcap_if_t* device, pcap_t* handle) {
	bpf_u_int32 netmask;
	struct bpf_program fcode;

	if (device->addresses != NULL)
		netmask = ((struct sockaddr_in *)(device->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	//compile the filter
	if (pcap_compile(handle, &fcode, "igmp", 1, netmask) < 0) {
		std::cerr << "\nUnable to compile the packet filter. Check the syntax.\n";
		return -1;
	}

	//set the filter
	if (pcap_setfilter(handle, &fcode) < 0) {
		std::cerr << "\nError setting the filter.\n";
		return -1;
	}
	return 0;
}

int main() {
	setlocale(LC_ALL, "Rus");
	//std::cout << sizeof(u_int) << ' ' << sizeof(udp_header) << '\n';
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum = 0;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_dumper_t *dumpfile;

	/* Load Npcap and its functions. */
	if (!LoadNpcapDlls()) {
		std::cerr << "Couldn't load Npcap\n";
		exit(1);
	}

	/* Retrieve the device list on the local machine */
	if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
		std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next) {
		std::cout << ++i << ". " << d->name;
		if (d->description)
			std::cout << " (" << d->description << ")\n";
		else
			std::cout << " (No description available)\n";
	}

	if (i == 0) {
		std::cout << "\nNo interfaces found! Make sure Npcap is installed.\n";
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs; inum < i; d = d->next, inum++) {
		if (std::string(d->description).find("NdisWan Adapter") == -1)
			break;
	}

	if (i == inum) {
		std::cout << "\nThere are no valid interfaces.\n";
		return -1;
	}

	/* Open the device */
	if ((adhandle = pcap_open(d->name,			            // name of the device
		                      65536,			            // portion of the packet to capture
					                                        // 65536 guarantees that the whole packet will be captured on all the link layers
		                      PCAP_OPENFLAG_PROMISCUOUS, 	// promiscuous mode
		                      1000,				            // read timeout
		                      NULL,				            // authentication on the remote machine
		                      errbuf			            // error buffer
	                          )) == NULL) {
		std::cerr << "\nUnable to open the adapter. " << d->name << " is not supported by Npcap\n";
		pcap_freealldevs(alldevs);
		return -1;
	}

	dumpfile = pcap_dump_open(adhandle, "dump.txt");

	/* Check the link layer. We support only Ethernet. */
	if (pcap_datalink(adhandle) != DLT_EN10MB) {
		std::cerr << "\nThis program works only on Ethernet networks.\n";
		pcap_freealldevs(alldevs);
		return -1;
	}

	//Activating the filter if needed
	std::cout << "Do you want to use filter?\n";
	while (true) {
		std::cout << "Y/y for \"yes\", N/n for \"no\": ";
		std::string use_filter;
		std::getline(std::cin, use_filter);
		if (use_filter == "Y" || use_filter == "y") {
			if (filter_on(d, adhandle) == -1) {
				pcap_freealldevs(alldevs);
				return -1;
			}
			break;
		}
		else if (use_filter == "N" || use_filter == "n") {
			break;
		}
	}

	std::cout << "\nlistening on " << d->description << "...\n\n";
	pcap_freealldevs(alldevs);
	pcap_loop(adhandle, 0, packet_handler, (unsigned char *)dumpfile);
	return 0;
}
