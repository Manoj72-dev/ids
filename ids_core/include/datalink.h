#ifndef DATALINK_H
#define DATALINK_H

#include <stdint.h>
#include <pcap/pcap.h>
#include "platform.h"
#include "pkt_info.h"

#define ETH_HDR_LEN   14
#define VLAN_TAG_LEN  4
#define VLAN_TPID     0x8100
#define QINQ_TPID     0x88A8

struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  scr[6];
    uint16_t type;
};

struct vlan_tag_hdr {
    uint16_t tpid;
    uint16_t tci;
    uint16_t type;
};

struct qinq_hdr {
    uint16_t outer_tpid;
    uint16_t outer_tci;
    uint16_t inner_tpid;
    uint16_t inner_tci;
    uint16_t type;
};

int parse_datalink(int linktype,
                   const u_char *pkt,
                   int caplen,
                   pkt_info *p);

#endif
