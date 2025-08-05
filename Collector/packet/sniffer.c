#include<stdio.h>
#include<pcap.h>
#include<windows.h>


int main(){
    pcap_if_t *alldevs,*dev;
    char errbuf[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&alldevs, errbuf) == -1){
        printf("Error: %s\n",errbuf);
        return 1;
    }
    for(dev = alldevs; dev ;dev = dev->next){
        printf("%s", dev->name);
        if(dev-> description){
            printf("- %s",dev->description);
        }
        printf("\n");
    }
    printf("completed\n");
    return 1;
}