#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include "../include/capture.h"
#include "../include/alerts.h"
#include "../include/packet.h"
#include "../include/rules.h"

static int g_capture_verbose = 0;
static int g_capture_daemon_mode = 0;
static int g_capture_log_packets = 0;
static pcap_t *g_capture_handle = NULL;
static char g_capture_interface[PACKET_IFACE_STRLEN] = "";

static void capture_log(FILE *stream, const char *fmt, ...)
{
    va_list args;

    if (g_capture_daemon_mode) {
        char timestamp[32];
        time_t now;
        struct tm *local_time;

        now = time(NULL);
        local_time = localtime(&now);
        if (local_time != NULL) {
            strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", local_time);
            fprintf(stream, "[%s] ", timestamp);
        }
    }

    va_start(args, fmt);
    vfprintf(stream, fmt, args);
    va_end(args);
    fflush(stream);
}

static void handle_capture_signal(int signal_number)
{
    (void)signal_number;

    if (g_capture_handle != NULL) {
        pcap_breakloop(g_capture_handle);
    }
}

static const char *ether_type_name(unsigned short ether_type)
{
    switch (ether_type) {
        case ETHERTYPE_IP:
            return "IPv4";
        case ETHERTYPE_ARP:
            return "ARP";
        case ETHERTYPE_IPV6:
            return "IPv6";
        default:
            return "Unknown";
    }
}

static const char *ip_protocol_name(unsigned char protocol)
{
    switch (protocol) {
        case IPPROTO_TCP:
            return "TCP";
        case IPPROTO_UDP:
            return "UDP";
        case IPPROTO_ICMP:
            return "ICMP";
        case IPPROTO_ICMPV6:
            return "ICMPv6";
        case IPPROTO_IGMP:
            return "IGMP";
        default:
            return "Unknown";
    }
}

static void mac_to_string(const u_char *mac, char *buffer, size_t buffer_size)
{
    snprintf(buffer, buffer_size, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void print_tcp_flags(unsigned char flags)
{
    const unsigned char tcp_ece = 0x40;
    const unsigned char tcp_cwr = 0x80;

    capture_log(stdout, " flags=");
    if (flags & TH_FIN) {
        capture_log(stdout, "FIN ");
    }
    if (flags & TH_SYN) {
        capture_log(stdout, "SYN ");
    }
    if (flags & TH_RST) {
        capture_log(stdout, "RST ");
    }
    if (flags & TH_PUSH) {
        capture_log(stdout, "PSH ");
    }
    if (flags & TH_ACK) {
        capture_log(stdout, "ACK ");
    }
    if (flags & TH_URG) {
        capture_log(stdout, "URG ");
    }
    if (flags & tcp_ece) {
        capture_log(stdout, "ECE ");
    }
    if (flags & tcp_cwr) {
        capture_log(stdout, "CWR ");
    }
}

static int should_output_packet_logs(void)
{
    if (g_capture_daemon_mode) {
        return g_capture_log_packets;
    }

    return g_capture_verbose;
}

static int parse_tcp(const u_char *packet, unsigned int remaining_len, PacketInfo *info)
{
    const struct tcphdr *tcp_header;
    unsigned int header_len;

    if (remaining_len < sizeof(struct tcphdr)) {
        capture_log(stdout, "TCP header truncated\n");
        return 0;
    }

    tcp_header = (const struct tcphdr *)packet;
    header_len = (unsigned int)tcp_header->doff * 4U;
    if (header_len < sizeof(struct tcphdr) || remaining_len < header_len) {
        capture_log(stdout, "Invalid TCP header length\n");
        return 0;
    }

    info->src_port = ntohs(tcp_header->source);
    info->dst_port = ntohs(tcp_header->dest);
    info->tcp_seq = ntohl(tcp_header->seq);
    info->tcp_ack = ntohl(tcp_header->ack_seq);
    info->tcp_flags = packet[13];
    info->tcp_window = ntohs(tcp_header->window);

    return 1;
}

static int parse_udp(const u_char *packet, unsigned int remaining_len, PacketInfo *info)
{
    const struct udphdr *udp_header;

    if (remaining_len < sizeof(struct udphdr)) {
        capture_log(stdout, "UDP header truncated\n");
        return 0;
    }

    udp_header = (const struct udphdr *)packet;
    info->src_port = ntohs(udp_header->source);
    info->dst_port = ntohs(udp_header->dest);

    return 1;
}

static int parse_icmpv4_info(const u_char *packet, unsigned int remaining_len, PacketInfo *info)
{
    const struct icmphdr *icmp_header;

    if (remaining_len < sizeof(struct icmphdr)) {
        capture_log(stdout, "ICMP header truncated\n");
        return 0;
    }

    icmp_header = (const struct icmphdr *)packet;
    info->icmp_type = icmp_header->type;
    info->icmp_code = icmp_header->code;
    return 1;
}

static int parse_icmpv6_info(const u_char *packet, unsigned int remaining_len, PacketInfo *info)
{
    const struct icmp6_hdr *icmp6_header;

    if (remaining_len < sizeof(struct icmp6_hdr)) {
        capture_log(stdout, "ICMPv6 header truncated\n");
        return 0;
    }

    icmp6_header = (const struct icmp6_hdr *)packet;
    info->icmp_type = icmp6_header->icmp6_type;
    info->icmp_code = icmp6_header->icmp6_code;
    return 1;
}

static int parse_arp(const u_char *packet, unsigned int remaining_len, PacketInfo *info)
{
    const struct ether_arp *arp_header;

    if (remaining_len < sizeof(struct ether_arp)) {
        capture_log(stdout, "ARP header truncated\n");
        return 0;
    }

    arp_header = (const struct ether_arp *)packet;
    info->has_arp = 1;
    info->arp_opcode = ntohs(arp_header->ea_hdr.ar_op);
    inet_ntop(AF_INET, arp_header->arp_spa, info->src_ip, sizeof(info->src_ip));
    inet_ntop(AF_INET, arp_header->arp_tpa, info->dst_ip, sizeof(info->dst_ip));

    return 1;
}

static int parse_ipv4(const u_char *packet, unsigned int remaining_len, PacketInfo *info)
{
    const struct ip *ip_header;
    unsigned int ip_header_len;

    if (remaining_len < sizeof(struct ip)) {
        capture_log(stdout, "IPv4 header truncated\n");
        return 0;
    }

    ip_header = (const struct ip *)packet;
    ip_header_len = (unsigned int)ip_header->ip_hl * 4U;
    if (ip_header_len < sizeof(struct ip) || remaining_len < ip_header_len) {
        capture_log(stdout, "Invalid IPv4 header length\n");
        return 0;
    }

    info->ip_version = 4;
    info->ip_protocol = ip_header->ip_p;
    info->ttl = ip_header->ip_ttl;
    info->ip_total_len = ntohs(ip_header->ip_len);
    info->ip_id = ntohs(ip_header->ip_id);
    info->ip_fragment = ntohs(ip_header->ip_off);
    inet_ntop(AF_INET, &ip_header->ip_src, info->src_ip, sizeof(info->src_ip));
    inet_ntop(AF_INET, &ip_header->ip_dst, info->dst_ip, sizeof(info->dst_ip));

    switch (ip_header->ip_p) {
        case IPPROTO_TCP:
            return parse_tcp(packet + ip_header_len, remaining_len - ip_header_len, info);
        case IPPROTO_UDP:
            return parse_udp(packet + ip_header_len, remaining_len - ip_header_len, info);
        case IPPROTO_ICMP:
            return parse_icmpv4_info(packet + ip_header_len, remaining_len - ip_header_len, info);
        default:
            return 1;
    }
}

static int parse_ipv6(const u_char *packet, unsigned int remaining_len, PacketInfo *info)
{
    const struct ip6_hdr *ip6_header;

    if (remaining_len < sizeof(struct ip6_hdr)) {
        capture_log(stdout, "IPv6 header truncated\n");
        return 0;
    }

    ip6_header = (const struct ip6_hdr *)packet;
    info->ip_version = 6;
    info->ip_protocol = ip6_header->ip6_nxt;
    info->ttl = ip6_header->ip6_hops;
    info->ip_total_len = ntohs(ip6_header->ip6_plen);
    inet_ntop(AF_INET6, &ip6_header->ip6_src, info->src_ip, sizeof(info->src_ip));
    inet_ntop(AF_INET6, &ip6_header->ip6_dst, info->dst_ip, sizeof(info->dst_ip));

    switch (ip6_header->ip6_nxt) {
        case IPPROTO_TCP:
            return parse_tcp(packet + sizeof(struct ip6_hdr),
                             remaining_len - sizeof(struct ip6_hdr), info);
        case IPPROTO_UDP:
            return parse_udp(packet + sizeof(struct ip6_hdr),
                             remaining_len - sizeof(struct ip6_hdr), info);
        case IPPROTO_ICMPV6:
            return parse_icmpv6_info(packet + sizeof(struct ip6_hdr),
                                     remaining_len - sizeof(struct ip6_hdr), info);
        default:
            return 1;
    }
}

static int parse_ethernet(const u_char *packet, unsigned int packet_len, PacketInfo *info)
{
    const struct ether_header *eth_header;

    if (packet_len < sizeof(struct ether_header)) {
        capture_log(stdout, "Packet too short for Ethernet header\n");
        return 0;
    }

    eth_header = (const struct ether_header *)packet;
    info->ether_type = ntohs(eth_header->ether_type);
    info->packet_len = packet_len;
    info->captured_len = packet_len;
    mac_to_string(eth_header->ether_shost, info->src_mac, sizeof(info->src_mac));
    mac_to_string(eth_header->ether_dhost, info->dst_mac, sizeof(info->dst_mac));

    switch (info->ether_type) {
        case ETHERTYPE_IP:
            return parse_ipv4(packet + sizeof(struct ether_header),
                              packet_len - sizeof(struct ether_header), info);
        case ETHERTYPE_ARP:
            return parse_arp(packet + sizeof(struct ether_header),
                             packet_len - sizeof(struct ether_header), info);
        case ETHERTYPE_IPV6:
            return parse_ipv6(packet + sizeof(struct ether_header),
                              packet_len - sizeof(struct ether_header), info);
        default:
            return 1;
    }
}

static void print_packet_summary(const PacketInfo *info)
{
    capture_log(stdout, "Ethernet src=%s dst=%s type=0x%04x (%s)\n",
                info->src_mac, info->dst_mac, info->ether_type, ether_type_name(info->ether_type));

    if (info->has_arp) {
        capture_log(stdout, "ARP opcode=%u sender_ip=%s target_ip=%s\n",
                    info->arp_opcode, info->src_ip, info->dst_ip);
        return;
    }

    if (info->ip_version != 0) {
        capture_log(stdout, "IPv%d src=%s dst=%s ttl=%u proto=%s total_len=%u",
                    info->ip_version,
                    info->src_ip,
                    info->dst_ip,
                    info->ttl,
                    ip_protocol_name(info->ip_protocol),
                    info->ip_total_len);

        if (info->ip_version == 4) {
            capture_log(stdout, " id=%u frag=0x%04x", info->ip_id, info->ip_fragment);
        }
        capture_log(stdout, "\n");
    }

    switch (info->ip_protocol) {
        case IPPROTO_TCP:
            capture_log(stdout, "TCP src_port=%u dst_port=%u seq=%u ack=%u window=%u",
                        info->src_port, info->dst_port, info->tcp_seq, info->tcp_ack, info->tcp_window);
            print_tcp_flags(info->tcp_flags);
            capture_log(stdout, "\n");
            break;
        case IPPROTO_UDP:
            capture_log(stdout, "UDP src_port=%u dst_port=%u\n", info->src_port, info->dst_port);
            break;
        case IPPROTO_ICMP:
            capture_log(stdout, "ICMP type=%u code=%u\n", info->icmp_type, info->icmp_code);
            break;
        case IPPROTO_ICMPV6:
            capture_log(stdout, "ICMPv6 type=%u code=%u\n", info->icmp_type, info->icmp_code);
            break;
        default:
            break;
    }
}

static void handle_packet(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet)
{
    PacketInfo info;
    RuleAlert alerts[MAX_RULE_ALERTS];
    size_t alert_count;
    size_t i;

    (void)user_data;

    packet_info_init(&info);
    snprintf(info.interface, sizeof(info.interface), "%s", g_capture_interface);
    info.packet_len = header->len;
    info.captured_len = header->caplen;

    if (!parse_ethernet(packet, header->caplen, &info)) {
        if (should_output_packet_logs()) {
            capture_log(stdout, "Captured packet: caplen=%u len=%u\n", header->caplen, header->len);
            capture_log(stdout, "Parser could not fully decode packet\n\n");
        }
        return;
    }

    if (should_output_packet_logs()) {
        capture_log(stdout, "Captured packet: caplen=%u len=%u\n", header->caplen, header->len);
        print_packet_summary(&info);
    }
    alert_count = evaluate_rules(&info, alerts, MAX_RULE_ALERTS);
    for (i = 0; i < alert_count; i++) {
        append_alert_log(&alerts[i], &info);
        capture_log(stdout, "ALERT [%s] severity=%s %s\n",
                    alerts[i].rule_name, alerts[i].severity, alerts[i].message);
    }
    if (should_output_packet_logs() || alert_count > 0) {
        capture_log(stdout, "\n");
    }
}

int open_interface(const char *interface_name, const char *protocol, int packet_count,
                   int verbose, int daemon_mode, int log_packets, const char *rule_file)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    struct bpf_program fp;
    bpf_u_int32 net = 0;
    int result;
    int loop_count;

    handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        capture_log(stderr, "Error: Could not open interface %s: %s\n", interface_name, errbuf);
        return 1;
    }

    if (packet_count == 0) {
        loop_count = -1;
    } else if (packet_count > 0) {
        loop_count = packet_count;
    } else {
        loop_count = CAPTURE_DEFAULT_PACKET_COUNT;
    }
    g_capture_verbose = verbose;
    g_capture_daemon_mode = daemon_mode;
    g_capture_log_packets = log_packets;
    snprintf(g_capture_interface, sizeof(g_capture_interface), "%s", interface_name);

    if (g_capture_verbose) {
        capture_log(stdout, "Verbose mode enabled\n");
        capture_log(stdout, "Monitoring interface: %s\n", interface_name);
    }
    if (g_capture_log_packets && g_capture_daemon_mode) {
        capture_log(stdout, "Packet capture logging enabled\n");
    }

    if (load_rules_file(rule_file) > 0) {
        if (g_capture_verbose) {
            capture_log(stdout, "Loaded rules from %s\n", rule_file);
        }
    } else if (g_capture_verbose) {
        capture_log(stdout, "No rules loaded from %s\n", rule_file);
    }

    signal(SIGINT, handle_capture_signal);
    signal(SIGTERM, handle_capture_signal);
    g_capture_handle = handle;

    if (protocol != NULL && protocol[0] != '\0') {
        if (pcap_compile(handle, &fp, protocol, 0, net) == -1) {
            capture_log(stderr, "Error: could not compile filter %s: %s\n",
                        protocol, pcap_geterr(handle));
            g_capture_handle = NULL;
            pcap_close(handle);
            return 1;
        }

        if (pcap_setfilter(handle, &fp) == -1) {
            capture_log(stderr, "Error: could not apply filter %s: %s\n",
                        protocol, pcap_geterr(handle));
            pcap_freecode(&fp);
            g_capture_handle = NULL;
            pcap_close(handle);
            return 1;
        }

        if (g_capture_verbose) {
            capture_log(stdout, "Applied filter: %s\n", protocol);
        }
        pcap_freecode(&fp);
    }

    if (g_capture_verbose) {
        if (loop_count == -1) {
            capture_log(stdout, "Packet count: continuous\n");
            capture_log(stdout, "Capturing continuously until interrupted...\n");
        } else {
            capture_log(stdout, "Packet count: %d\n", loop_count);
            capture_log(stdout, "Capturing up to %d packets...\n", loop_count);
        }
    }

    result = pcap_loop(handle, loop_count, handle_packet, NULL);
    if (result == -1) {
        capture_log(stderr, "Error: capture failed on %s: %s\n", interface_name, pcap_geterr(handle));
        g_capture_handle = NULL;
        pcap_close(handle);
        return 1;
    }
    if (result == 0 && g_capture_verbose) {
        capture_log(stdout, "Capture finished.\n");
    }

    unload_rules_file();
    g_capture_handle = NULL;
    g_capture_daemon_mode = 0;
    g_capture_log_packets = 0;
    g_capture_interface[0] = '\0';
    pcap_close(handle);
    return 0;
}
