#include <string.h>
#include "datalink.h"

static int parse_ethernet(const u_char *pkt, int caplen, pkt_info *p)
{
    if (caplen < ETH_HDR_LEN)
        return -1;

    const struct eth_hdr *eth = (const struct eth_hdr *)pkt;
    
    memcpy(p->src_mac, eth->scr, 6);
    memcpy(p->dst_mac, eth->dst, 6);

    p->l2_offset = ETH_HDR_LEN;
    p->l2_proto  = ntohs(eth->type);

    if (p->l2_proto == VLAN_TPID) {
        const struct vlan_tag_hdr *v =
            (const struct vlan_tag_hdr *)(pkt + ETH_HDR_LEN);

        p->vlan_id = ntohs(v->tci) & 0x0FFF;
        p->l2_offset += VLAN_TAG_LEN;
        p->l2_proto = ntohs(v->type);
    }

    return 0;
}

int parse_datalink(int linktype, const u_char *pkt, int caplen, pkt_info *p)
{
    if (linktype == DLT_EN10MB)
        return parse_ethernet(pkt, caplen, p);

    return -1;
}
