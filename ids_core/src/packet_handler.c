#include "packet_handler.h"
#include "datalink.h"
#include "network.h"
#include "transport.h"
#include "rules.h"
#include "alerts.h"
#include "ml_bridge.h"

void handle_packet(const struct pcap_pkthdr *header,
                   const unsigned char *packet,
                   int linktype)
{
    pkt_info p = {0};

    p.packet_len = header->caplen;

    if (parse_datalink(linktype, packet, header->caplen, &p) != 0)
        return;

    if (parse_network_layer(p.l2_proto,
                            packet + p.l2_offset,
                            header->caplen - p.l2_offset,
                            &p) != 0)
        return;

    if (parse_transport_layer(p.ip_proto,
                              packet + p.l3_offset,
                              header->caplen - p.l3_offset,
                              &p) != 0)
        return;

    rules_check(&p);

    if (ml_predict_from_packet(&p) > 0.8)
        alerts_push("⚠ ML: anomaly detected");
}
