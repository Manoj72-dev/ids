#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <pcap/pcap.h>
#include "platform.h"
#include "pkt_info.h"

struct arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t  hlen;
    uint8_t  plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint8_t  spa[4];
    uint8_t  tha[6];
    uint8_t  tpa[4];
};

struct ipv4_hdr {
    uint8_t  ver_ihl;
    uint8_t  tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t flag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint8_t  src[4];
    uint8_t  dst[4];
};

struct ipv6_hdr {
    uint32_t ver_tc_flow;
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
};

int parse_network_layer(uint16_t l2_proto,
                        const u_char *pkt,
                        int caplen,
                        pkt_info *p);

#endif
