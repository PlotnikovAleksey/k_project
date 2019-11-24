#include <iostream>
#include <iomanip>
#include <pcap.h>
//#include <Winsock2.h>
#include <tchar.h>
#include <string>
#include <sstream>
#include <vector>
#include <algorithm>
#include <time.h>
#include <cstdint>
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
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;
	uint8_t byte4;
	uint8_t byte5;
	uint8_t byte6;

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
	uint16_t protocol_type;
};

/* 4 bytes IP address */
class ipv4_address {
public:
	uint8_t byte1;
	uint8_t byte2;
	uint8_t byte3;
	uint8_t byte4;

	void print_ip_addr() {
		std::cout << static_cast<int>(byte1) << '.' << static_cast<int>(byte2) <<
			'.' << static_cast<int>(byte3) << '.' << static_cast<int>(byte4);
	}
};

/* IPv4 header */
class ipv4_header {
public:
	uint8_t	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	uint8_t	tos;			// Type of service 
	uint16_t tlen;			// Total length 
	uint16_t identification; // Identification
	uint16_t flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	uint8_t	ttl;			// Time to live
	uint8_t	proto;			// Protocol
	uint16_t crc;			// Header checksum
	ipv4_address saddr;		// Source address
	ipv4_address daddr;		// Destination address
	uint32_t op_pad;			// Option + Padding
};

/* ARP header */
class arp_header {
public:
	uint16_t	hard_type;		  // Hardware type
	uint16_t proto;			  // Protocol type 
	uint8_t hard_len;          // Hardware length
	uint8_t proto_len;         // Protocol length
	uint16_t operation;        // Operation
	mac_address sender_mac;   // Sender hardware address
	ipv4_address sender_ip;   // Sender protocol address
	mac_address target_mac;   // Target hardware address
	ipv4_address target_ip;   // Target protocol address
};

/* UDP header*/
class udp_header {
public:
	uint16_t sport;			// Source port
	uint16_t dport;			// Destination port
	uint16_t len;			// Datagram length
	uint16_t crc;			// Checksum
};

/* TCP header*/
class tcp_header {
public:
	uint16_t sport;			        // Source port
	uint16_t dport;			        // Destination port
	uint32_t seq_number;               // Порядковый номер
	uint32_t acknowledgment_number;    // Номер подтверждения
	uint16_t different_info;         // 0 - 3 Длина заголовка, 4 - 9 Зарезервировано, 10 - 15 Флаги
	uint16_t window_size;            // Размер Окна
	uint16_t crc;			        // Checksum
	uint16_t urgent_ptr;             // Указатель важности
};

/* IGMP header*/
class igmp_header {
public:
	uint8_t type;                 // Тип
	uint8_t max_resp_code;        // Код макс. ответа
	uint16_t crc;                 // Контрольная сумма
	ipv4_address group_address;  // Групповой адрес
};

/* ICMP header*/
class icmp_header {
public:
	uint8_t type;                 // Тип
	uint8_t code;                 // Код
	uint16_t crc;                 // Контрольная сумма
};

void parce_udp(const uint8_t *pkt_data, uint32_t prev_header_len) {
	uint16_t sport, dport, len;
	udp_header* udp_h = (udp_header *)((uint8_t*)pkt_data + 14 + prev_header_len);
	sport = ntohs(udp_h->sport);
	dport = ntohs(udp_h->dport);
	len = ntohs(udp_h->len);
	std::cout << "\nUser Datagram Protocol, Scr port: " << sport << ", Dst port: " << dport << ", Len: " << len << "\n";
}

void parce_tcp(const struct pcap_pkthdr *header, const uint8_t *pkt_data, uint32_t prev_header_len) {
	uint16_t sport, dport;
	tcp_header* tcp_h = (tcp_header *)((uint8_t*)pkt_data + 14 + prev_header_len);
	sport = ntohs(tcp_h->sport);
	dport = ntohs(tcp_h->dport);
	uint16_t different_info = ntohs(tcp_h->different_info);
	uint16_t window_size = ntohs(tcp_h->window_size);
	uint16_t tcp_header_len = (different_info >> 12) * 4;
	uint16_t tcp_payload_len = header->len - 14 - prev_header_len - tcp_header_len;
	std::cout << "\nTransmission Control Protocol, Scr port: " << sport << ", Dst port: " << dport << ", Win: " << window_size << ", Payload len: " << tcp_payload_len << "\n";
}

void parce_igmp(const uint8_t *pkt_data, uint32_t prev_header_len) {
	igmp_header* igmp_h = (igmp_header *)((uint8_t*)pkt_data + 14 + prev_header_len);
	std::cout << "\nInternet Group Management Protocol";
	if (igmp_h->type == 0x11) {
		std::cout << "\nMembership query, ";
	}
	else if (igmp_h->type == 0x16 || igmp_h->type == 0x17) {
		std::cout << " version 2\n";
		if (igmp_h->type == 0x16)
			std::cout << "Membership report, ";
		else
			std::cout << "Leave Group, ";
	}
	else if (igmp_h->type == 0x22) {
		std::cout << " version 3\nMembership Report, ";
	}
	else {
		std::cout << " unknown version\n";
	}
	std::cout << "multicast address: ";
	igmp_h->group_address.print_ip_addr();
	std::cout << std::endl;
}

void parce_icmp(const uint8_t *pkt_data, uint32_t prev_header_len) {
	icmp_header* icmp_h = (icmp_header*)((uint8_t*)pkt_data + 14 + prev_header_len);
	std::cout << "\nInternet Control Message Protocol, ";
	if (static_cast<int>(icmp_h->type) == 0 && static_cast<int>(icmp_h->code) == 0) {
		std::cout << "Echo Reply";
	}
	else if (static_cast<int>(icmp_h->type) == 3) {
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
	}
	else if (static_cast<int>(icmp_h->type) == 5) {
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
	}
	else if (static_cast<int>(icmp_h->type) == 8 && static_cast<int>(icmp_h->code) == 0) {
		std::cout << "Echo Request";
	}
	else if (static_cast<int>(icmp_h->type) == 9 && static_cast<int>(icmp_h->code) == 0) {
		std::cout << "Router Advertisement";
	}
	else if (static_cast<int>(icmp_h->type) == 10 && static_cast<int>(icmp_h->code) == 0) {
		std::cout << "Router Solicitation";
	}
	else if (static_cast<int>(icmp_h->type) == 11) {
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
	}
	else if (static_cast<int>(icmp_h->type) == 11) {
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
    }
	else if (static_cast<int>(icmp_h->type) == 13 && static_cast<int>(icmp_h->code) == 0) {
	std::cout << "Timestamp";
	}
	else if (static_cast<int>(icmp_h->type) == 14 && static_cast<int>(icmp_h->code) == 0) {
	std::cout << "Timestamp Reply";
	}
	else if (static_cast<int>(icmp_h->type) == 40) {
	std::cout << "Photuris, Security failures";
	}
	else if (static_cast<int>(icmp_h->type) == 42 && static_cast<int>(icmp_h->code) == 0) {
	std::cout << "Extended Echo Request";
	}
	else if (static_cast<int>(icmp_h->type) == 43) {
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
	}
	else {
	std::cout << "unknown type";
    }
	std::cout << std::endl;
}

size_t packet_num = 0;

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(uint8_t *dump, const struct pcap_pkthdr *header, const uint8_t *pkt_data) {
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
		uint32_t ip_header_len = (ip_h->ver_ihl & 0xf) * 4;
		std::cout << "\nInternet Protocol v. 4, ";
		ip_h->saddr.print_ip_addr();
		std::cout << " -> ";
		ip_h->daddr.print_ip_addr();
		//udp
		if (static_cast<int>(ip_h->proto) == 17) {
			parce_udp(pkt_data, ip_header_len);
		}
		//tcp
		else if (static_cast<int>(ip_h->proto) == 6) {
			parce_tcp(header, pkt_data, ip_header_len);
		}
		//icmp
		else if (static_cast<int>(ip_h->proto) == 1) {
			parce_icmp(pkt_data, ip_header_len);
		}
		//igmp
		else if (static_cast<int>(ip_h->proto) == 2) {
			parce_igmp(pkt_data, ip_header_len);
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
	if (pcap_compile(handle, &fcode, "icmp", 1, netmask) < 0) {
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
	//std::cout << sizeof(uint32_t) << ' ' << sizeof(udp_header) << '\n';
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
	pcap_loop(adhandle, 0, packet_handler, (uint8_t *)dumpfile);
	return 0;
}
