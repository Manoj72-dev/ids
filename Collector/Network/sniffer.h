#ifndef SNIFFER_H
#define SNIFFER_H

#include <winsock2.h>
#include<windows.h>
#include<ws2tcpip.h>
#include<pcap.h>

#define ETHERNET_HEADER_LEN 14
#define VLAN_TAG_LEN 4
#define IPv6_HEADER_LEN 40

struct eth_header{
    u_char dest[6]; //destination mac-address
    u_char src[6];  //host mac- address
    u_short type;  //
};

struct ip6_header{
    u_int ver_tc_fl;
    u_short payload_len;
    u_char next_header;
    u_char hop_limit;
    struct in6_addr src_ip;
    struct in6_addr dest_ip;
};

struct ip4_header{
    u_char ver_ihl; //version (4 bits) + internet header length (4 bits)
    u_char tos; //type of servies   
    u_short tlen ; //total length
    u_short identification; // Identification 
    u_short flags_fo; // Flags(3 bits) + Fragment offset (13 bits)
    u_char ttl;  //time to live
    u_char proto; //Protocol
    u_short crc; //checksum
    struct in_addr src_ip; //source address
    struct in_addr dest_ip; //Destination address
};

struct tcp_header{
    u_short sport;  //source port
    u_short dport;  // destination port
    u_int seq; // sequence number
    u_int ack; // ack number
    u_char data_offset_reserved;  
    u_char flags; 
    u_short win; // window size
    u_short checksum; 
    u_short urg_ptr; // urgent pointer to the data that is urgent
};

struct udp_header{
    u_short sport;
    u_short dport;
    u_short len;
    u_short checksum;
};

struct icmp_header{
    u_char type;
    u_char code;
    u_short checksum;
    u_short id;
    u_short sequence;
};

struct igmp_header{
    u_char type;
    u_char code;
    u_short checksum;
    struct in_addr group_address;
};

struct vlan_tag{
    u_short tci;
    u_short type;
};

void parse_udp_header(char *packet_info, int offset, const u_char *packet);
void parse_tcp_header(char *packet_info, int offset, const u_char *packet);
void parse_icmp_header(char *packet_info, int offset, const u_char *packet);
void parse_igmp_header(char *packet_info, int offset, const u_char *packet);
void parse_ip4_header(char *packet_info,int offset, const u_char *packet);
void parse_ip6_header(char *packet_info, int offset, const char *packet);
void packet_handler(const struct pcap_pkthdr *header, const u_char *pkt_data);
DWORD WINAPI capture_packets(LPVOID wifidev);

#endif // SNIFFER_H