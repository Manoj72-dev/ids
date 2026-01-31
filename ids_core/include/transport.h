#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdint.h>
#include <pcap/pcap.h>
#include "platform.h"
#include "pkt_info.h"

#define TCP_HDR_LEN(tcp) (((tcp)->offset_res >> 4) * 4)

struct udp_hdr {
    uint16_t src;
    uint16_t dst;
    uint16_t len;
    uint16_t chk;
};

struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq;
    uint32_t ack;
    uint8_t  offset_res;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgptr;
};

struct icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
};

int parse_transport_layer(uint8_t proto,
                           const u_char *pkt,
                           int caplen,
                           pkt_info *p);

#endif
