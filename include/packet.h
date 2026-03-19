#ifndef PACKET_H
#define PACKET_H

#define PACKET_MAC_STRLEN 18
#define PACKET_IP_STRLEN  46
#define PACKET_IFACE_STRLEN 32

typedef struct
{
    char interface[PACKET_IFACE_STRLEN];
    unsigned short ether_type;
    unsigned short packet_len;
    unsigned short captured_len;

    int has_arp;
    unsigned short arp_opcode;
    unsigned char icmp_type;
    unsigned char icmp_code;

    int ip_version;
    unsigned char ip_protocol;
    unsigned char ttl;
    unsigned short ip_total_len;
    unsigned short ip_id;
    unsigned short ip_fragment;

    unsigned short src_port;
    unsigned short dst_port;
    unsigned char tcp_flags;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned short tcp_window;

    char src_mac[PACKET_MAC_STRLEN];
    char dst_mac[PACKET_MAC_STRLEN];
    char src_ip[PACKET_IP_STRLEN];
    char dst_ip[PACKET_IP_STRLEN];
} PacketInfo;

void packet_info_init(PacketInfo *info);

#endif
