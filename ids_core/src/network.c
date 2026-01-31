#include <string.h>
#include "network.h"

static int parse_ipv4(const u_char *pkt, int caplen, pkt_info *p)
{
    const struct ipv4_hdr *ip = (const struct ipv4_hdr *)pkt;

    uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
    if (ihl < 20 || caplen < ihl)
        return -1;

    p->l3_proto = 0x0800;
    p->ip_proto = ip->protocol;
    p->ip_ttl   = ip->ttl;

    memcpy(&p->src_ip, ip->src, 4);
    memcpy(&p->dst_ip, ip->dst, 4);

    p->l3_offset = p->l2_offset + ihl;

    return 0;
}

static int parse_ipv6(const u_char *pkt, int caplen, pkt_info *p)
{
    const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)pkt;

    p->l3_proto = 0x86DD;
    p->ip_proto = ip6->next_header;
    p->ip_ttl   = ip6->hop_limit;

    p->l3_offset = p->l2_offset + 40;

    return 0;
}

int parse_network_layer(uint16_t l2_proto, const u_char *pkt, int caplen, pkt_info *p)
{
    if (l2_proto == 0x0800)
        return parse_ipv4(pkt, caplen, p);

    if (l2_proto == 0x86DD)
        return parse_ipv6(pkt, caplen, p);

    return -1;
}
