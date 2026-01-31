#include "transport.h"

static int parse_tcp(const u_char *pkt, int caplen, pkt_info *p)
{
    const struct tcp_hdr *tcp = (const struct tcp_hdr *)pkt;

    int hlen = TCP_HDR_LEN(tcp);
    if (hlen < 20 || caplen < hlen)
        return -1;

    p->l4_proto   = 6;
    p->src_port   = ntohs(tcp->src);
    p->dst_port   = ntohs(tcp->dst);
    p->tcp_flags  = tcp->flags;
    p->tcp_seq    = ntohl(tcp->seq);
    p->tcp_ack    = ntohl(tcp->ack);
    p->tcp_window = ntohs(tcp->window);

    p->l4_offset = p->l3_offset + hlen;
    p->payload   = pkt + hlen;
    p->payload_len = caplen - hlen;

    return 0;
}

static int parse_udp(const u_char *pkt, int caplen, pkt_info *p)
{
    const struct udp_hdr *udp = (const struct udp_hdr *)pkt;

    p->l4_proto   = 17;
    p->src_port   = ntohs(udp->src);
    p->dst_port   = ntohs(udp->dst);
    p->udp_length = ntohs(udp->len);

    p->l4_offset = p->l3_offset + sizeof(struct udp_hdr);
    p->payload   = pkt + sizeof(struct udp_hdr);
    p->payload_len = caplen - sizeof(struct udp_hdr);

    return 0;
}

int parse_transport_layer(uint8_t proto, const u_char *pkt, int caplen, pkt_info *p)
{
    if (proto == 6)
        return parse_tcp(pkt, caplen, p);

    if (proto == 17)
        return parse_udp(pkt, caplen, p);

    return -1;
}
