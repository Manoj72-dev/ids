#ifndef PACKET_HANDLER_H
#define PACKET_HANDLER_H

#include <pcap/pcap.h>
#include "pkt_info.h"

void handle_packet(const struct pcap_pkthdr *header,
                   const unsigned char *packet,
                   int linktype);

#endif
