#include<stdio.h>
#include<pcap.h>
#include<windows.h>
#include<winsock2.h>
#include<ws2tcpip.h>
#include <stdint.h>
#include<stdlib.h>


#define ETHERNET_HEADER_LEN 14
#define VLAN_TAG_LEN 4

struct eth_header{
    u_char dest[6]; //destination mac-address
    u_char src[6];  //host mac- address
    u_short type;  //
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
    u_char data_offset;  
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
};

struct igmp_hdr{
    u_char type;
    u_char code;
    u_short checksum;
    struct in_addr group_address;
};

struct vlan_tag{
    u_short tci;
    u_short type;
};


void parse_ip4_header(char *packet_info,int offset, const u_char *packet){
    struct ip4_header *ip = (struct ip4_header *) (packet + offset);
    char src_ip_str[INET_ADDRSTRLEN];
    char dest_ip_str[INET_ADDRSTRLEN];

    strcpy(src_ip_str, inet_ntoa(ip->src_ip));
    strcpy(dest_ip_str, inet_ntoa(ip->dest_ip));
    
    sprintf(packet_info + strlen(packet_info)," SRC_IP: %s ; DEST_IP: %s ; PROTO: %d ; TTL: %d ; TLEN: %d ; ID: %d",src_ip_str,dest_ip_str, ip->proto,ip->ttl, ntohs(ip->tlen), ntohs(ip->identification));
    
    printf("%s\n",packet_info);
    
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
    else{
        printf("ipv6\n");
    }
    
}



DWORD WINAPI capture_packets(LPVOID wifidev){
    pcap_if_t * device = (pcap_if_t *)wifidev;
    pcap_t *handel;
    struct bpf_program fp;
    bpf_u_int32 net;
    const char *filter_exp = "ip or ip6 and (tcp or udp or icmp)";
    char errbuf[PCAP_ERRBUF_SIZE];

    handel = pcap_open_live(device->name,65536,1,1000,errbuf);

    if (pcap_compile(handel, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handel));
        return 2;
    }
    if (pcap_setfilter(handel, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handel));
        return 2;
    }

    if(handel == NULL){
        printf("Canot open the Devices %s: %s\n",device->name,errbuf);
        exit(1);
    }
    printf("Opened the Device\n");

    struct pcap_pkthdr *header;
    const u_char *data;
    int res;

    while((res = pcap_next_ex(handel, &header, &data)) >= 0){
        if(res == 0) continue;
        packet_handler(header,data);
    }
    pcap_close(handel);
    return 0;
}

int main(){
    pcap_if_t *alldevs,*wifidev, *ethdev, *dev; // variables to store devices in the machine (in a linklist)//
    char errbuf[PCAP_ERRBUF_SIZE];  // errbuf to store the errors //

    if(pcap_findalldevs(&alldevs, errbuf) == -1){ // pcap_findalldevs() scan machice and store all the devices that are in the machine in alldevs //
        printf("Error: %s\n",errbuf);  //alldevs have alldevs->name, alldevs->addresses, alldevs->description, alldevs->flags, alldevs->next//
        return 1;
    }
    int i=1;
    for(dev = alldevs; dev ;dev= dev->next){
        if(i ==5){
            wifidev = dev;
            printf("Devices selected: %s\n",dev->description);
        }
        i++;
    }

    DWORD threadId1;
    HANDLE hThread1 = CreateThread(NULL,0,capture_packets,wifidev,0,&threadId1) ;
    
    if(hThread1 == NULL){
        fprintf(stderr,"CreateThread Failed. Error: %lu\n",GetLastError());
        return 1;
    }
    printf("Thread created\n");

    WaitForSingleObject(hThread1,INFINITE);
    CloseHandle(hThread1);
    return 1;
}