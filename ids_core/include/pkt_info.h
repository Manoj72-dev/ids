#ifndef PKT_INFO_H
#define PKT_INFO_H

#include <stdint.h>

typedef struct {

    uint32_t l2_offset;
    uint32_t l3_offset;
    uint32_t l4_offset;
    uint32_t packet_len;
    uint16_t l2_proto;
    uint16_t vlan_id;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint16_t l3_proto;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  ip_ttl;
    uint8_t  ip_proto;
    uint16_t l4_proto;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  tcp_flags;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_window;
    uint16_t udp_length;
    uint8_t  icmp_type;
    uint8_t  icmp_code;
    const unsigned char *payload;
    uint32_t payload_len;
    uint64_t timestamp;
    uint64_t flow_id;
    uint8_t malformed;
    uint8_t is_fragmented;
    uint8_t is_retransmission;

    float anomaly_score;

} pkt_info;

#endif
