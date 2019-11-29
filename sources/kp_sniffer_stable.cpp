// Copyright 2019 Plotnikov Aleksey <alex280201@gmail.com>

#include <kp_sniffer_stable.hpp>

size_t packet_num = 0;

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(uint8_t *dump, const struct pcap_pkthdr *header,
                    const uint8_t *pkt_data) {
  struct tm *ltime;
  char timestr[16];
  time_t local_tv_sec;
  pcap_dump(dump, header, pkt_data);
  local_tv_sec = header->ts.tv_sec;
  ltime = localtime(&local_tv_sec);
  strftime(timestr, sizeof(timestr), "%H:%M:%S", ltime);
  std::cout << ++packet_num << ") Capture time is " << timestr << ','
            << " length of the packet: " << header->len << std::endl;
}

int filter_on(pcap_if_t *device, pcap_t *handle, char *filter) {
  bpf_u_int32 subnet;
  bpf_u_int32 netmask;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fcode;
  if (pcap_lookupnet(device->name, &subnet, &netmask, errbuf) == -1) {
    std::cerr << "Can't get netmask for device " << device->description << "\n";
    subnet = 0;
    netmask = 0;
  }
  // compile the filter
  if (pcap_compile(handle, &fcode, filter, 1, netmask) < 0) return -1;
  // set the filter
  pcap_setfilter(handle, &fcode);
  return 0;
}

int sniffing(char *user_filter, uint32_t packet_num) {
  setlocale(LC_ALL, "Rus");
  pcap_if_t *alldevs;
  pcap_if_t *d;
  pcap_t *adhandle;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_dumper_t *dumpfile;

  /* Retrieve the device list on the local machine */
  if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1) {
    std::cerr << "Error in pcap_findalldevs: " << errbuf << std::endl;
    return -1;
  }

  /* Jump to the adapter */
  for (d = alldevs; d; d = d->next) {
    if (static_cast<int>(std::string(d->description).find("NdisWan Adapter")) ==
        -1)
      break;
  }

  if (d == nullptr) {
    std::cout << "\nThere are no valid interfaces.\n";
    pcap_freealldevs(alldevs);
    return -1;
  }

  /* Open the device */
  if ((adhandle = pcap_open(d->name,  // name of the device
                            65536,    // portion of the packet to capture
                                      // 65536 guarantees that the whole packet
                                      // will be captured on all the link layers
                            PCAP_OPENFLAG_PROMISCUOUS,  // promiscuous mode
                            1000,                       // read timeout
                            NULL,   // authentication on the remote machine
                            errbuf  // error buffer
                            )) == NULL) {
    std::cerr << "\nUnable to open the adapter. " << d->name
              << " is not supported by Npcap\n";
    pcap_freealldevs(alldevs);
    return -1;
  }

  dumpfile = pcap_dump_open(adhandle, "dump.ydp");

  /* Check the link layer. We support only Ethernet. */
  if (pcap_datalink(adhandle) != 1) {
    std::cerr << "\nThis program works only on Ethernet networks.\n";
    pcap_freealldevs(alldevs);
    return -1;
  }

  // Activating the filter if needed
  char *used_filter;
  char base_filter[] = "ip || ip6 || arp";
  if (user_filter == nullptr)
    used_filter = base_filter;
  else
    used_filter = user_filter;
  if (filter_on(d, adhandle, used_filter) == -1) {
    pcap_freealldevs(alldevs);
    return 2;
  }
  std::cout << "\nlistening on " << d->description << "...\n\n";
  pcap_freealldevs(alldevs);
  pcap_loop(adhandle, packet_num, packet_handler, (uint8_t *)dumpfile);
  return 0;
}
