#include<stdio.h>
#include<pcap.h>
#include<windows.h>
#include<winsock2.h>
#include<ws2tcpip.h>
#include<stdint.h>
#include<stdlib.h>

#include "sniffer.h"

void parse_udp_header(char *packet_info, int offset, const u_char *packet) {
    struct udp_header *udp = (struct udp_header *)(packet + offset);
    sprintf(packet_info + strlen(packet_info), " ; UDP_SRC_PORT: %d ; UDP_DEST_PORT: %d ; UDP_LEN: %d", ntohs(udp->sport), ntohs(udp->dport), ntohs(udp->len));
}

void parse_tcp_header(char *packet_info, int offset, const u_char *packet){
    struct tcp_header *tcp = (struct tcp_header *)(packet + offset);
    u_short sport = ntohs(tcp->sport);
    u_short dport = ntohs(tcp->dport);
    u_short win = ntohs(tcp->win);
    u_char tcp_offset = (tcp->data_offset_reserved >> 4) * 4; // TCP header length in bytes
    u_char flags = tcp->flags;

    sprintf(packet_info + strlen(packet_info),
            " TCP SRC_PORT: %d ; DST_PORT: %d ; FLAGS: 0x%02X ; WIN: %d ; HLEN: %d",
            sport, dport, flags, win, tcp_offset);
}

void parse_icmp_header(char *packet_info, int offset, const u_char *packet){
    struct icmp_header *icmp = (struct icmp_header *)(packet + offset);
    sprintf(packet_info + strlen(packet_info), " ICMP_TYPE: %d ; CODE: %d", icmp->type, icmp->code);

}

void parse_igmp_header(char *packet_info, int offset, const u_char *packet){
    struct igmp_header *igmp = (struct igmp_header *)(packet + offset);
    sprintf(packet_info + strlen(packet_info),
    " IGMP_TYPE: %d ; GROUP_ADDR: %s ",
    igmp->type, inet_ntoa(igmp->group_address));
}


void parse_ip4_header(char *packet_info,int offset, const u_char *packet){
    struct ip4_header *ip = (struct ip4_header *) (packet + offset);
    char src_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];

    strcpy(src_ip_str, inet_ntoa(ip->src_ip));
    strcpy(dest_ip_str, inet_ntoa(ip->dest_ip));
    u_char ihl = ip->ver_ihl & 0X0F;
    offset += ihl*4;
    sprintf(packet_info + strlen(packet_info),"IP_VER: 4 ; SRC_IP: %s ; DEST_IP: %s ; PROTO: %d ; TTL: %d ; TLEN: %d ; ID: %d",src_ip_str,dest_ip_str, ip->proto,ip->ttl, ntohs(ip->tlen), ntohs(ip->identification));
    
    switch(ip->proto){
        case 17: 
            parse_udp_header(packet_info,offset,packet);
            break;
        case 6:
            parse_tcp_header(packet_info,offset,packet);
            break;
        case 2:
            parse_igmp_header(packet_info,offset,packet);
            break;
        case 1:
            parse_icmp_header(packet_info,offset,packet);
            break;
        default:
            return;
    }
    
}

void parse_ip6_header(char *packet_info, int offset, const char *packet){
    struct ip6_header *ip = (struct ip6_header *)(packet + offset);
    offset += IPv6_HEADER_LEN;
    
    char src_ip[INET6_ADDRSTRLEN];
    char dest_ip[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6,&(ip->src_ip),src_ip, sizeof(src_ip));
    inet_ntop(AF_INET6,&(ip->dest_ip),dest_ip, sizeof(dest_ip));

    sprintf(packet_info + strlen(packet_info),"IP_VER: 6 ;SRC_IP: %s ; DEST_IP: %s ; PROTO: %d ; HOP_LIMIT: %d ; PAYLOAD_LEN: %d", src_ip, dest_ip, ip->next_header, ip->hop_limit, ntohs(ip->payload_len));
    switch (ip->next_header){
        case 6:
            parse_tcp_header(packet_info,offset,packet);
            break;
        case 17:
            parse_udp_header(packet_info,offset,packet);
            break;
        default:
            return;
    }
    
}


void packet_handler(const struct pcap_pkthdr *header, const u_char *pkt_data){
    char packet_info[1024] = "";

    int offset = 0;
    struct eth_header *eth = (struct eth_header *)pkt_data;

    sprintf(packet_info + strlen(packet_info), "SRC_MAC:%02x:%02x:%02x:%02x:%02x:%02x;",
            eth->src[0], eth->src[1], eth->src[2], eth->src[3], eth->src[4], eth->src[5]);

    sprintf(packet_info + strlen(packet_info), "DST_MAC:%02x:%02x:%02x:%02x:%02x:%02x;",
            eth->dest[0], eth->dest[1], eth->dest[2], eth->dest[3], eth->dest[4], eth->dest[5]);
    
    offset += ETHERNET_HEADER_LEN;
    u_short type= ntohs(eth->type);
     
    if (type == 0x8100){
        struct vlan_tag *vlan = (struct vlan_tag *)(pkt_data + offset);
        sprintf(packet_info + strlen(packet_info), "VLAN_ID: %d",ntohs(vlan->tci & 0x0FFF));

        type = ntohs(vlan->type);
        offset += VLAN_TAG_LEN;
    }
    if(type == 0x0800){
        parse_ip4_header(packet_info, offset, pkt_data);
    }
    else if(type == 0x86DD){
        parse_ip6_header(packet_info, offset,pkt_data);
    }
    printf("%s\n", packet_info);
}




DWORD WINAPI capture_packets(LPVOID Param){
    pcap_if_t *alldevs,*wifidev, *dev; // variables to store devices in the machine (in a linklist)//
    char errbuf[PCAP_ERRBUF_SIZE];  // errbuf to store the errors //

    if(pcap_findalldevs(&alldevs, errbuf) == -1){ // pcap_findalldevs() scan machice and store all the devices that are in the machine in alldevs //
        printf("Error: %s\n",errbuf);  //alldevs have alldevs->name, alldevs->addresses, alldevs->description, alldevs->flags, alldevs->next//
        return 1;
    }
    int i=1;
    for(dev = alldevs; dev ;dev= dev->next){
        if(i == 5){
            wifidev = dev;
            printf("Devices selected: %s\n",dev->description);
        }
        i++;
    }
    
    pcap_t *handle;
    struct bpf_program fp;
    bpf_u_int32 net, mask;

    if (pcap_lookupnet(wifidev->name, &net, &mask, errbuf) == -1) {
        net = 0;
        mask = 0;
    }
    const char *filter_exp = "ip or ip6";

    handle = pcap_open_live(wifidev->name,65536,1,0,errbuf);
    if(handle == NULL){
        printf("Canot open the Devices %s: %s\n",wifidev->name,errbuf);
        exit(1);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 2;
    }

    struct pcap_pkthdr *header;
    const u_char *data;
    int res;

    while((res = pcap_next_ex(handle, &header, &data)) >= 0){
        if(res == 0){ 
            continue;
        }
        packet_handler(header,data);
    }
    pcap_close(handle);
    return 0;
}
