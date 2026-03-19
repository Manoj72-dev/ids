#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "packet.h"
#include "rules.h"

#define MAX_RULES 64
#define MAX_RULE_COUNTERS 256
#define RULE_PROTO_LEN 16
#define RULE_IP_LEN 46

typedef struct
{
    int any;
    int start;
    int end;
} PortRange;

typedef struct
{
    int any;
    int is_cidr;
    int family;
    int prefix_len;
    char text[RULE_IP_LEN];
    union {
        struct in_addr ipv4;
        struct in6_addr ipv6;
    } addr;
} IpSpec;

typedef struct
{
    char action[16];
    char protocol[RULE_PROTO_LEN];
    IpSpec src_ip;
    PortRange src_port;
    char direction[3];
    IpSpec dst_ip;
    PortRange dst_port;
    char msg[RULE_MSG_LEN];
    char severity[RULE_SEVERITY_LEN];
    char flags[16];
    int icmp_type;
    int arp_opcode;
    int threshold;
    int sid;
} ParsedRule;

typedef struct
{
    int sid;
    char src_ip[PACKET_IP_STRLEN];
    unsigned int count;
} RuleCounter;

static ParsedRule g_rules[MAX_RULES];
static size_t g_rule_count = 0;
static RuleCounter g_rule_counters[MAX_RULE_COUNTERS];
static size_t g_rule_counter_count = 0;

static char *trim_whitespace(char *text)
{
    char *end;

    while (*text != '\0' && isspace((unsigned char)*text)) {
        text++;
    }

    if (*text == '\0') {
        return text;
    }

    end = text + strlen(text) - 1;
    while (end > text && isspace((unsigned char)*end)) {
        *end = '\0';
        end--;
    }

    return text;
}

static void ip_spec_init(IpSpec *spec)
{
    memset(spec, 0, sizeof(*spec));
    spec->any = 1;
    snprintf(spec->text, sizeof(spec->text), "any");
}

static void port_range_init(PortRange *range)
{
    range->any = 1;
    range->start = 0;
    range->end = 0;
}

static void parsed_rule_init(ParsedRule *rule)
{
    memset(rule, 0, sizeof(*rule));
    snprintf(rule->action, sizeof(rule->action), "alert");
    snprintf(rule->protocol, sizeof(rule->protocol), "any");
    ip_spec_init(&rule->src_ip);
    port_range_init(&rule->src_port);
    snprintf(rule->direction, sizeof(rule->direction), "->");
    ip_spec_init(&rule->dst_ip);
    port_range_init(&rule->dst_port);
    snprintf(rule->severity, sizeof(rule->severity), "medium");
    rule->icmp_type = -1;
    rule->arp_opcode = -1;
    rule->threshold = 1;
}

static int parse_int_token(const char *token, int default_value)
{
    if (token == NULL || *token == '\0' || strcasecmp(token, "any") == 0) {
        return default_value;
    }

    return atoi(token);
}

static void copy_quoted_value(char *dst, size_t dst_size, const char *value)
{
    size_t len;

    value = trim_whitespace((char *)value);
    len = strlen(value);
    if (len >= 2 && value[0] == '"' && value[len - 1] == '"') {
        value++;
        len -= 2;
    }

    snprintf(dst, dst_size, "%.*s", (int)len, value);
}

static int parse_ip_spec(const char *token, IpSpec *spec)
{
    char buffer[RULE_IP_LEN];
    char *slash;

    ip_spec_init(spec);

    if (strcasecmp(token, "any") == 0) {
        return 1;
    }

    snprintf(buffer, sizeof(buffer), "%s", token);
    slash = strchr(buffer, '/');
    if (slash != NULL) {
        *slash = '\0';
        spec->is_cidr = 1;
        spec->prefix_len = atoi(slash + 1);
    }

    if (inet_pton(AF_INET, buffer, &spec->addr.ipv4) == 1) {
        spec->family = AF_INET;
        spec->any = 0;
        if (!spec->is_cidr) {
            spec->prefix_len = 32;
        }
        snprintf(spec->text, sizeof(spec->text), "%s", token);
        return 1;
    }

    if (inet_pton(AF_INET6, buffer, &spec->addr.ipv6) == 1) {
        spec->family = AF_INET6;
        spec->any = 0;
        if (!spec->is_cidr) {
            spec->prefix_len = 128;
        }
        snprintf(spec->text, sizeof(spec->text), "%s", token);
        return 1;
    }

    return 0;
}

static int parse_port_range(const char *token, PortRange *range)
{
    char buffer[32];
    char *colon;

    port_range_init(range);

    if (strcasecmp(token, "any") == 0) {
        return 1;
    }

    snprintf(buffer, sizeof(buffer), "%s", token);
    colon = strchr(buffer, ':');
    if (colon == NULL) {
        range->any = 0;
        range->start = atoi(buffer);
        range->end = range->start;
        return 1;
    }

    *colon = '\0';
    range->any = 0;
    range->start = (*buffer == '\0') ? 0 : atoi(buffer);
    range->end = (*(colon + 1) == '\0') ? 65535 : atoi(colon + 1);
    if (range->start > range->end) {
        return 0;
    }

    return 1;
}

static void parse_rule_option(char *option_text, ParsedRule *rule)
{
    char *separator;
    char *key;
    char *value;

    separator = strchr(option_text, ':');
    if (separator == NULL) {
        return;
    }

    *separator = '\0';
    key = trim_whitespace(option_text);
    value = trim_whitespace(separator + 1);

    if (strcasecmp(key, "msg") == 0) {
        copy_quoted_value(rule->msg, sizeof(rule->msg), value);
    } else if (strcasecmp(key, "severity") == 0) {
        copy_quoted_value(rule->severity, sizeof(rule->severity), value);
    } else if (strcasecmp(key, "flags") == 0) {
        copy_quoted_value(rule->flags, sizeof(rule->flags), value);
    } else if (strcasecmp(key, "icmp_type") == 0) {
        rule->icmp_type = parse_int_token(value, -1);
    } else if (strcasecmp(key, "arp_opcode") == 0) {
        rule->arp_opcode = parse_int_token(value, -1);
    } else if (strcasecmp(key, "threshold") == 0) {
        rule->threshold = parse_int_token(value, 1);
    } else if (strcasecmp(key, "sid") == 0) {
        rule->sid = parse_int_token(value, 0);
    }
}

static RuleCounter *get_rule_counter(int sid, const char *src_ip)
{
    size_t i;

    for (i = 0; i < g_rule_counter_count; i++) {
        if (g_rule_counters[i].sid == sid &&
            strcmp(g_rule_counters[i].src_ip, src_ip) == 0) {
            return &g_rule_counters[i];
        }
    }

    if (g_rule_counter_count >= MAX_RULE_COUNTERS) {
        return NULL;
    }

    g_rule_counters[g_rule_counter_count].sid = sid;
    snprintf(g_rule_counters[g_rule_counter_count].src_ip,
             sizeof(g_rule_counters[g_rule_counter_count].src_ip), "%s", src_ip);
    g_rule_counters[g_rule_counter_count].count = 0;
    g_rule_counter_count++;
    return &g_rule_counters[g_rule_counter_count - 1];
}

static void parse_rule_options(char *options_text, ParsedRule *rule)
{
    char *option;

    option = strtok(options_text, ";");
    while (option != NULL) {
        option = trim_whitespace(option);
        if (*option != '\0') {
            parse_rule_option(option, rule);
        }
        option = strtok(NULL, ";");
    }
}

static int parse_rule_line(char *line, ParsedRule *rule)
{
    char *open_paren;
    char *close_paren;
    char *options_text;
    char src_ip_text[RULE_IP_LEN];
    char src_port_text[32];
    char dst_ip_text[RULE_IP_LEN];
    char dst_port_text[32];
    int scanned;

    parsed_rule_init(rule);

    open_paren = strchr(line, '(');
    close_paren = strrchr(line, ')');
    if (open_paren == NULL || close_paren == NULL || close_paren < open_paren) {
        return 0;
    }

    *open_paren = '\0';
    *close_paren = '\0';
    options_text = open_paren + 1;

    scanned = sscanf(line, "%15s %15s %45s %31s %2s %45s %31s",
                     rule->action,
                     rule->protocol,
                     src_ip_text,
                     src_port_text,
                     rule->direction,
                     dst_ip_text,
                     dst_port_text);
    if (scanned != 7) {
        return 0;
    }

    if (!parse_ip_spec(src_ip_text, &rule->src_ip) ||
        !parse_ip_spec(dst_ip_text, &rule->dst_ip) ||
        !parse_port_range(src_port_text, &rule->src_port) ||
        !parse_port_range(dst_port_text, &rule->dst_port)) {
        return 0;
    }

    parse_rule_options(options_text, rule);
    return 1;
}

static int protocol_matches(const ParsedRule *rule, const PacketInfo *info)
{
    if (strcasecmp(rule->protocol, "any") == 0) {
        return 1;
    }

    if (strcasecmp(rule->protocol, "arp") == 0) {
        return info->has_arp;
    }

    if (strcasecmp(rule->protocol, "ip") == 0) {
        return info->ip_version == 4 || info->ip_version == 6;
    }

    if (strcasecmp(rule->protocol, "tcp") == 0) {
        return info->ip_protocol == IPPROTO_TCP;
    }

    if (strcasecmp(rule->protocol, "udp") == 0) {
        return info->ip_protocol == IPPROTO_UDP;
    }

    if (strcasecmp(rule->protocol, "icmp") == 0) {
        return info->ip_protocol == IPPROTO_ICMP;
    }

    if (strcasecmp(rule->protocol, "icmp6") == 0 || strcasecmp(rule->protocol, "icmpv6") == 0) {
        return info->ip_protocol == IPPROTO_ICMPV6;
    }

    return 0;
}

static int ipv4_cidr_match(const struct in_addr *rule_addr, int prefix_len, const char *packet_ip)
{
    struct in_addr packet_addr;
    uint32_t mask;
    uint32_t rule_host;
    uint32_t packet_host;

    if (inet_pton(AF_INET, packet_ip, &packet_addr) != 1) {
        return 0;
    }

    if (prefix_len <= 0) {
        return 1;
    }

    mask = (prefix_len == 32) ? 0xFFFFFFFFu : (~0u << (32 - prefix_len));
    rule_host = ntohl(rule_addr->s_addr);
    packet_host = ntohl(packet_addr.s_addr);
    return (rule_host & mask) == (packet_host & mask);
}

static int ipv6_cidr_match(const struct in6_addr *rule_addr, int prefix_len, const char *packet_ip)
{
    struct in6_addr packet_addr;
    int full_bytes;
    int remaining_bits;

    if (inet_pton(AF_INET6, packet_ip, &packet_addr) != 1) {
        return 0;
    }

    if (prefix_len <= 0) {
        return 1;
    }

    full_bytes = prefix_len / 8;
    remaining_bits = prefix_len % 8;

    if (full_bytes > 0 &&
        memcmp(rule_addr->s6_addr, packet_addr.s6_addr, (size_t)full_bytes) != 0) {
        return 0;
    }

    if (remaining_bits > 0) {
        unsigned char mask = (unsigned char)(0xFFu << (8 - remaining_bits));

        if ((rule_addr->s6_addr[full_bytes] & mask) != (packet_addr.s6_addr[full_bytes] & mask)) {
            return 0;
        }
    }

    return 1;
}

static int ip_matches(const IpSpec *rule_ip, const char *packet_ip)
{
    if (rule_ip->any) {
        return 1;
    }

    if (rule_ip->family == AF_INET) {
        return ipv4_cidr_match(&rule_ip->addr.ipv4, rule_ip->prefix_len, packet_ip);
    }

    if (rule_ip->family == AF_INET6) {
        return ipv6_cidr_match(&rule_ip->addr.ipv6, rule_ip->prefix_len, packet_ip);
    }

    return 0;
}

static int port_matches(const PortRange *rule_port, unsigned short packet_port)
{
    if (rule_port->any) {
        return 1;
    }

    return (int)packet_port >= rule_port->start && (int)packet_port <= rule_port->end;
}

static int flags_match(const char *rule_flags, unsigned char packet_flags)
{
    size_t i;

    if (rule_flags[0] == '\0') {
        return 1;
    }

    for (i = 0; rule_flags[i] != '\0'; i++) {
        switch (toupper((unsigned char)rule_flags[i])) {
            case 'S':
                if ((packet_flags & TH_SYN) == 0) {
                    return 0;
                }
                break;
            case 'A':
                if ((packet_flags & TH_ACK) == 0) {
                    return 0;
                }
                break;
            case 'F':
                if ((packet_flags & TH_FIN) == 0) {
                    return 0;
                }
                break;
            case 'R':
                if ((packet_flags & TH_RST) == 0) {
                    return 0;
                }
                break;
            case 'P':
                if ((packet_flags & TH_PUSH) == 0) {
                    return 0;
                }
                break;
            case 'U':
                if ((packet_flags & TH_URG) == 0) {
                    return 0;
                }
                break;
            case '0':
                if (packet_flags != 0) {
                    return 0;
                }
                break;
            default:
                break;
        }
    }

    return 1;
}

static int endpoint_match(const ParsedRule *rule,
                          const char *src_ip, unsigned short src_port,
                          const char *dst_ip, unsigned short dst_port,
                          const PacketInfo *info)
{
    if (!ip_matches(&rule->src_ip, src_ip) || !ip_matches(&rule->dst_ip, dst_ip)) {
        return 0;
    }

    if (!info->has_arp) {
        if (!port_matches(&rule->src_port, src_port) || !port_matches(&rule->dst_port, dst_port)) {
            return 0;
        }

        if (rule->icmp_type != -1 && rule->icmp_type != (int)info->icmp_type) {
            return 0;
        }

        if (!flags_match(rule->flags, info->tcp_flags)) {
            return 0;
        }
    } else if (rule->arp_opcode != -1 && rule->arp_opcode != (int)info->arp_opcode) {
        return 0;
    }

    return 1;
}

static int rule_matches(const ParsedRule *rule, const PacketInfo *info)
{
    RuleCounter *counter;

    if (strcasecmp(rule->action, "alert") != 0) {
        return 0;
    }

    if (!protocol_matches(rule, info)) {
        return 0;
    }

    if (endpoint_match(rule, info->src_ip, info->src_port, info->dst_ip, info->dst_port, info)) {
        goto threshold_check;
    }

    if (strcmp(rule->direction, "<>") == 0 &&
        endpoint_match(rule, info->dst_ip, info->dst_port, info->src_ip, info->src_port, info)) {
        goto threshold_check;
    }

    return 0;

threshold_check:
    if (rule->threshold <= 1 || rule->sid <= 0) {
        return 1;
    }

    counter = get_rule_counter(rule->sid, info->src_ip);
    if (counter == NULL) {
        return 0;
    }

    counter->count++;
    if (counter->count < (unsigned int)rule->threshold) {
        return 0;
    }

    return (counter->count % (unsigned int)rule->threshold) == 0;
}

static void build_alert_message(const ParsedRule *rule, const PacketInfo *info, RuleAlert *alert)
{
    const char *msg;
    char limited_msg[128];

    rule_alert_init(alert);
    alert->matched = 1;
    alert->sid = rule->sid;
    if (rule->sid > 0) {
        snprintf(alert->rule_name, sizeof(alert->rule_name), "%s#%d",
                 rule->protocol, rule->sid);
    } else {
        snprintf(alert->rule_name, sizeof(alert->rule_name), "%s_rule", rule->protocol);
    }
    snprintf(alert->protocol, sizeof(alert->protocol), "%s", rule->protocol);
    snprintf(alert->severity, sizeof(alert->severity), "%s", rule->severity);

    msg = (rule->msg[0] != '\0') ? rule->msg : "Rule matched";
    snprintf(limited_msg, sizeof(limited_msg), "%.120s", msg);
    if (info->has_arp) {
        snprintf(alert->message, sizeof(alert->message), "%s %s -> %s",
                 limited_msg, info->src_ip, info->dst_ip);
    } else if (info->src_port != 0 || info->dst_port != 0) {
        snprintf(alert->message, sizeof(alert->message), "%s %s:%u -> %s:%u",
                 limited_msg, info->src_ip, info->src_port, info->dst_ip, info->dst_port);
    } else {
        snprintf(alert->message, sizeof(alert->message), "%s %s -> %s",
                 limited_msg, info->src_ip, info->dst_ip);
    }
}

int load_rules_file(const char *path)
{
    FILE *file;
    char line[512];

    g_rule_count = 0;
    g_rule_counter_count = 0;

    file = fopen(path, "r");
    if (file == NULL) {
        return 0;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *cursor;
        ParsedRule rule;

        cursor = trim_whitespace(line);
        if (*cursor == '\0' || *cursor == '#') {
            continue;
        }

        if (g_rule_count >= MAX_RULES) {
            break;
        }

        if (parse_rule_line(cursor, &rule)) {
            g_rules[g_rule_count] = rule;
            g_rule_count++;
        }
    }

    fclose(file);
    return (int)g_rule_count;
}

void unload_rules_file(void)
{
    g_rule_count = 0;
    g_rule_counter_count = 0;
}

void packet_info_init(PacketInfo *info)
{
    memset(info, 0, sizeof(*info));
}

void rule_alert_init(RuleAlert *alert)
{
    memset(alert, 0, sizeof(*alert));
}

size_t evaluate_rules(const PacketInfo *info, RuleAlert *alerts, size_t max_alerts)
{
    size_t i;
    size_t alert_count;

    alert_count = 0;
    for (i = 0; i < max_alerts; i++) {
        rule_alert_init(&alerts[i]);
    }

    for (i = 0; i < g_rule_count; i++) {
        if (rule_matches(&g_rules[i], info)) {
            if (alert_count >= max_alerts) {
                break;
            }
            build_alert_message(&g_rules[i], info, &alerts[alert_count]);
            alert_count++;
        }
    }

    return alert_count;
}
