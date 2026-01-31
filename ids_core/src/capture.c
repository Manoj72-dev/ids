#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "../include/ids_api.h"
#include "../include/packet_handler.h"

extern volatile int stop_flag;

void *capture_thread_func(void *arg){
    char *iface = (char *)arg;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    handle = pcap_open_live(iface, 65536, 1, 10, errbuf);
    if (!handle) {
        printf("ERROR opening interface %s: %s\n", iface, errbuf);
        free(iface);
        return NULL;
    }

    int linktype = pcap_datalink(handle);
    printf("Capture started on %s (link=%d)\n", iface, linktype);

    while (!stop_flag) {
        struct pcap_pkthdr *header;
        const unsigned char *data;
        int res = pcap_next_ex(handle, &header, &data);
        
        if (res == 0) continue;
        if (res < 0) break;

        handle_packet(header, data, linktype);
    }

    printf("Capture stopped.\n");
    pcap_close(handle);
    free(iface);
    return NULL;
}