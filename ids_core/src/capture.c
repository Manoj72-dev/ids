#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "../include/ids_api.h"
#include "../include/packet_handler.h"

extern volatile int stop_flag;
void *capture_thread_func(void *arg)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;

    pcap_if_t *alldevs;
    pcap_if_t *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        printf("pcap_findalldevs failed: %s\n", errbuf);
        return NULL;
    }

    if (!alldevs) {
        printf("No interfaces found\n");
        return NULL;
    }

    /* pick first device */
    d = alldevs;

    printf("Using device: %s\n", d->name);

    handle = pcap_create(d->name, errbuf);
    if (!handle) {
        printf("pcap_create failed: %s\n", errbuf);
        pcap_freealldevs(alldevs);
        return NULL;
    }

    pcap_freealldevs(alldevs);

    pcap_set_snaplen(handle, 65536);
    pcap_set_promisc(handle, 1);
    pcap_set_timeout(handle, 10);

    if (pcap_activate(handle) != 0) {
        printf("pcap_activate failed: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return NULL;
    }

    int linktype = pcap_datalink(handle);
    printf("Capture started (link=%d)\n", linktype);

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
    return NULL;
}

