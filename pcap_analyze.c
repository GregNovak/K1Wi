#include "pcap_analyze.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>





static uint16_t read_u16_le(const unsigned char *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint16_t read_u16_be(const unsigned char *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_u32_le(const unsigned char *p)
{
    return ((uint32_t)p[0]) |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t read_u32_be(const unsigned char *p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) |
           ((uint32_t)p[3]);
}

static uint16_t read_u16(const unsigned char *p, int little_endian)
{
    return little_endian ? read_u16_le(p) : read_u16_be(p);
}

static uint32_t read_u32(const unsigned char *p, int little_endian)
{
    return little_endian ? read_u32_le(p) : read_u32_be(p);
}

static const char *link_type_name(uint32_t link_type)
{
    switch (link_type) {
        case 1:
            return "Ethernet";
        case 101:
            return "Raw IP";
        case 105:
            return "IEEE 802.11";
        case 113:
            return "Linux cooked capture";
        case 127:
            return "Radiotap";
        case 228:
            return "IPv4";
        case 229:
            return "IPv6";
        default:
            return "Unknown/other";
    }
}

#define K1WI_PCAP_MAX_IPS 64
#define K1WI_PCAP_MAX_PORTS 64
#define K1WI_PCAP_PREVIEW_SIZE 128
#define K1WI_PCAP_MAX_TCP_FRAGMENTS 512
#define K1WI_PCAP_MAX_RECON_BYTES 8192

struct ip_counter {
    uint32_t ip;
    uint64_t count;
};

#define K1WI_PCAP_MAX_PORTS 64

struct port_counter {
    uint16_t port;
    uint64_t count;
};

struct tcp_fragment {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint64_t packet_index;
    uint32_t ts_sec;
    uint32_t ts_usec;

    unsigned char *payload;
    size_t payload_len;

    unsigned char *decoded_payload;
    size_t decoded_payload_len;
    int has_decoded_payload;
};

static void add_port_count(struct port_counter *table, size_t table_size, uint16_t port)
{
    for (size_t i = 0; i < table_size; i++) {
        if (table[i].count > 0 && table[i].port == port) {
            table[i].count++;
            return;
        }
    }

    for (size_t i = 0; i < table_size; i++) {
        if (table[i].count == 0) {
            table[i].port = port;
            table[i].count = 1;
            return;
        }
    }
}

static void print_port_table(const char *title, const struct port_counter *table, size_t table_size)
{
    int printed_indices[5] = {-1, -1, -1, -1, -1};

    printf("\n%s\n", title);
    printf("-------------------\n");

    for (size_t rank = 0; rank < 5; rank++) {
        size_t best = table_size;
        uint64_t best_count = 0;

        for (size_t i = 0; i < table_size; i++) {
            int already_printed = 0;

            for (size_t j = 0; j < rank; j++) {
                if (printed_indices[j] == (int)i) {
                    already_printed = 1;
                    break;
                }
            }

            if (!already_printed && table[i].count > best_count) {
                best = i;
                best_count = table[i].count;
            }
        }

        if (best == table_size || best_count == 0) {
            break;
        }

        printed_indices[rank] = (int)best;
        printf("%-15u  %llu\n",
               (unsigned int)table[best].port,
               (unsigned long long)table[best].count);
    }

    if (printed_indices[0] == -1) {
        printf("n/a\n");
    }
}


static int is_ascii_whitespace(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

static int is_printable_payload(const unsigned char *data, size_t len)
{
    size_t printable = 0;

    if (!data || len == 0) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];

        if ((c >= 32u && c <= 126u) || c == '\r' || c == '\n' || c == '\t') {
            printable++;
        }
    }

    return printable * 100u >= len * 85u;
}

static void make_ascii_preview(const unsigned char *data,
                               size_t len,
                               char *out,
                               size_t out_size)
{
    size_t pos = 0;

    if (!out || out_size == 0) {
        return;
    }

    if (!data || len == 0) {
        out[0] = '\0';
        return;
    }

    for (size_t i = 0; i < len && pos + 1 < out_size; i++) {
        unsigned char c = data[i];

        if (c >= 32u && c <= 126u) {
            out[pos++] = (char)c;
        } else if (c == '\r') {
            out[pos++] = ' ';
        } else if (c == '\n') {
            out[pos++] = ' ';
        } else if (c == '\t') {
            out[pos++] = ' ';
        } else {
            out[pos++] = '.';
        }
    }

    out[pos] = '\0';
}

static int base64_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (int)(c - 'A');
    }

    if (c >= 'a' && c <= 'z') {
        return (int)(c - 'a') + 26;
    }

    if (c >= '0' && c <= '9') {
        return (int)(c - '0') + 52;
    }

    if (c == '+') {
        return 62;
    }

    if (c == '/') {
        return 63;
    }

    if (c == '=') {
        return -2;
    }

    return -1;
}

static int looks_like_base64_payload(const unsigned char *data, size_t len)
{
    size_t clean_len = 0;
    int seen_padding = 0;

    if (!data || len < 4) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];

        if (is_ascii_whitespace(c)) {
            continue;
        }

        int v = base64_value(c);

        if (v == -1) {
            return 0;
        }

        if (c == '=') {
            seen_padding = 1;
        } else if (seen_padding) {
            return 0;
        }

        clean_len++;
    }

    return clean_len >= 4 && clean_len % 4u == 0u;
}

static int decode_base64_preview(const unsigned char *data,
                                 size_t len,
                                 unsigned char *out,
                                 size_t out_size,
                                 size_t *decoded_len)
{
    int quad[4];
    size_t quad_count = 0;
    size_t out_pos = 0;

    if (!data || !out || out_size == 0 || !decoded_len) {
        return 0;
    }

    *decoded_len = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = data[i];

        if (is_ascii_whitespace(c)) {
            continue;
        }

        int v = base64_value(c);

        if (v == -1) {
            return 0;
        }

        quad[quad_count++] = v;

        if (quad_count == 4) {
            if (quad[0] < 0 || quad[1] < 0) {
                return 0;
            }

            if (out_pos < out_size) {
                out[out_pos++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
            }

            if (quad[2] != -2) {
                if (quad[2] < 0) {
                    return 0;
                }

                if (out_pos < out_size) {
                    out[out_pos++] = (unsigned char)(((quad[1] & 0x0f) << 4) | (quad[2] >> 2));
                }
            }

            if (quad[3] != -2) {
                if (quad[2] < 0 || quad[3] < 0) {
                    return 0;
                }

                if (out_pos < out_size) {
                    out[out_pos++] = (unsigned char)(((quad[2] & 0x03) << 6) | quad[3]);
                }
            }

            quad_count = 0;
        }
    }

    if (quad_count != 0) {
        return 0;
    }

    *decoded_len = out_pos;
    return out_pos > 0;
}

static void format_ipv4(uint32_t ip, char *out, size_t out_size)
{
    snprintf(out,
             out_size,
             "%u.%u.%u.%u",
             (unsigned int)((ip >> 24) & 0xffu),
             (unsigned int)((ip >> 16) & 0xffu),
             (unsigned int)((ip >> 8) & 0xffu),
             (unsigned int)(ip & 0xffu));
}

static void format_tcp_flags(uint8_t flags, char *out, size_t out_size)
{
    struct tcp_flag_name {
        uint8_t mask;
        const char *name;
    };

    static const struct tcp_flag_name flag_names[] = {
        {0x01u, "FIN"},
        {0x02u, "SYN"},
        {0x04u, "RST"},
        {0x08u, "PSH"},
        {0x10u, "ACK"},
        {0x20u, "URG"}
    };

    size_t used = 0;
    size_t i;
    int first = 1;

    if (!out || out_size == 0u) {
        return;
    }

    out[0] = '\0';

    for (i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++) {
        int written;

        if ((flags & flag_names[i].mask) == 0u) {
            continue;
        }

        written = snprintf(out + used,
                           out_size - used,
                           "%s%s",
                           first ? "" : ",",
                           flag_names[i].name);

        if (written < 0 || (size_t)written >= out_size - used) {
            out[out_size - 1u] = '\0';
            return;
        }

        used += (size_t)written;
        first = 0;
    }

    if (first) {
        snprintf(out, out_size, "NONE");
    }
}

static void add_ip_count(struct ip_counter *table, size_t table_size, uint32_t ip)
{
    for (size_t i = 0; i < table_size; i++) {
        if (table[i].count > 0 && table[i].ip == ip) {
            table[i].count++;
            return;
        }
    }

    for (size_t i = 0; i < table_size; i++) {
        if (table[i].count == 0) {
            table[i].ip = ip;
            table[i].count = 1;
            return;
        }
    }
}

static void print_ip_table(const char *title, const struct ip_counter *table, size_t table_size)
{
    int printed_indices[5] = {-1, -1, -1, -1, -1};

    printf("\n%s\n", title);
    printf("-------------------\n");

    for (size_t rank = 0; rank < 5; rank++) {
        size_t best = table_size;
        uint64_t best_count = 0;

        for (size_t i = 0; i < table_size; i++) {
            int already_printed = 0;

            for (size_t j = 0; j < rank; j++) {
                if (printed_indices[j] == (int)i) {
                    already_printed = 1;
                    break;
                }
            }

            if (!already_printed && table[i].count > best_count) {
                best = i;
                best_count = table[i].count;
            }
        }

        if (best == table_size || best_count == 0) {
            break;
        }

        printed_indices[rank] = (int)best;

        char ip_buf[32];
        format_ipv4(table[best].ip, ip_buf, sizeof(ip_buf));
        printf("%-15s  %llu\n", ip_buf, (unsigned long long)table[best].count);
    }

    if (printed_indices[0] == -1) {
        printf("n/a\n");
    }
}
static int compare_tcp_fragments_by_seq(const void *a, const void *b)
{
    const struct tcp_fragment *fa = (const struct tcp_fragment *)a;
    const struct tcp_fragment *fb = (const struct tcp_fragment *)b;

    if (fa->seq < fb->seq) {
        return -1;
    }

    if (fa->seq > fb->seq) {
        return 1;
    }

    if (fa->packet_index < fb->packet_index) {
        return -1;
    }

    if (fa->packet_index > fb->packet_index) {
        return 1;
    }

    return 0;
}
static int compare_tcp_fragments_by_time(const void *a, const void *b)
{
    const struct tcp_fragment *fa = (const struct tcp_fragment *)a;
    const struct tcp_fragment *fb = (const struct tcp_fragment *)b;

    if (fa->ts_sec < fb->ts_sec) {
        return -1;
    }

    if (fa->ts_sec > fb->ts_sec) {
        return 1;
    }

    if (fa->ts_usec < fb->ts_usec) {
        return -1;
    }

    if (fa->ts_usec > fb->ts_usec) {
        return 1;
    }

    if (fa->packet_index < fb->packet_index) {
        return -1;
    }

    if (fa->packet_index > fb->packet_index) {
        return 1;
    }

    return 0;
}

static void free_tcp_fragments(struct tcp_fragment *fragments, size_t count)
{
    for (size_t i = 0; i < count; i++) {
        free(fragments[i].payload);
        fragments[i].payload = NULL;
        fragments[i].payload_len = 0;

        free(fragments[i].decoded_payload);
        fragments[i].decoded_payload = NULL;
        fragments[i].decoded_payload_len = 0;
        fragments[i].has_decoded_payload = 0;
    }
}

static void add_tcp_fragment(struct tcp_fragment *fragments,
                             size_t *fragment_count,
                             size_t max_fragments,
                             uint32_t src_ip,
                             uint32_t dst_ip,
                             uint16_t src_port,
                             uint16_t dst_port,
                             uint32_t seq,
                             uint64_t packet_index,
                             uint32_t ts_sec,
                             uint32_t ts_frac,
                             const unsigned char *payload,
                             size_t payload_len)
{
    if (!fragments || !fragment_count || !payload || payload_len == 0) {
        return;
    }

    if (*fragment_count >= max_fragments) {
        return;
    }

    unsigned char *copy = malloc(payload_len);

    if (!copy) {
        return;
    }

    for (size_t i = 0; i < payload_len; i++) {
        copy[i] = payload[i];
    }

    size_t idx = *fragment_count;

    fragments[idx].src_ip = src_ip;
    fragments[idx].dst_ip = dst_ip;
    fragments[idx].src_port = src_port;
    fragments[idx].dst_port = dst_port;
    fragments[idx].seq = seq;
    fragments[idx].packet_index = packet_index;
    fragments[idx].ts_sec = ts_sec;
    fragments[idx].ts_usec = ts_frac;  
    fragments[idx].payload = copy;
    fragments[idx].payload_len = payload_len;
    
    fragments[idx].decoded_payload = NULL;
    fragments[idx].decoded_payload_len = 0;
    fragments[idx].has_decoded_payload = 0;

    if (looks_like_base64_payload(payload, payload_len)) {
        unsigned char decoded[K1WI_PCAP_PREVIEW_SIZE];
        size_t decoded_len = 0;

        if (decode_base64_preview(payload,
                                  payload_len,
                                  decoded,
                                  sizeof(decoded),
                                  &decoded_len) &&
            decoded_len > 0 &&
            is_printable_payload(decoded, decoded_len)) {
            unsigned char *decoded_copy = malloc(decoded_len);

            if (decoded_copy) {
                for (size_t i = 0; i < decoded_len; i++) {
                    decoded_copy[i] = decoded[i];
                }

                fragments[idx].decoded_payload = decoded_copy;
                fragments[idx].decoded_payload_len = decoded_len;
                fragments[idx].has_decoded_payload = 1;
            }
        }
    }

    (*fragment_count)++;
}

static void print_decoded_fragment_reconstruction(const struct tcp_fragment *fragments,
                                                  size_t fragment_count,
                                                  const char *label)
{
    unsigned char decoded_reconstructed[K1WI_PCAP_MAX_RECON_BYTES];
    size_t decoded_recon_len = 0;
    size_t decoded_fragment_count = 0;

    for (size_t i = 0; i < fragment_count; i++) {
        if (!fragments[i].has_decoded_payload ||
            !fragments[i].decoded_payload ||
            fragments[i].decoded_payload_len == 0) {
            continue;
        }

        size_t copy_len = fragments[i].decoded_payload_len;

        if (copy_len > K1WI_PCAP_MAX_RECON_BYTES - decoded_recon_len) {
            copy_len = K1WI_PCAP_MAX_RECON_BYTES - decoded_recon_len;
        }

        for (size_t j = 0; j < copy_len; j++) {
            decoded_reconstructed[decoded_recon_len++] = fragments[i].decoded_payload[j];
        }

        decoded_fragment_count++;

        if (decoded_recon_len >= K1WI_PCAP_MAX_RECON_BYTES) {
            break;
        }
    }

    printf("\n%s\n", label);
    for (size_t i = 0; i < strlen(label); i++) {
        putchar('-');
    }
    putchar('\n');

    printf("Note: decodes each Base64-like TCP payload fragment separately before reconstruction.\n");
    printf("Decoded printable fragments: %zu\n", decoded_fragment_count);
    printf("Decoded reconstruction bytes: %zu\n", decoded_recon_len);

    if (decoded_recon_len > 0) {
        char decoded_recon_preview[K1WI_PCAP_MAX_RECON_BYTES];

        make_ascii_preview(decoded_reconstructed,
                           decoded_recon_len,
                           decoded_recon_preview,
                           sizeof(decoded_recon_preview));

        printf("Decoded reconstruction:\n");
        printf("%s\n", decoded_recon_preview);
    } else {
        printf("Decoded reconstruction: n/a\n");
    }
}

static void print_tcp_stream_reconstruction(struct tcp_fragment *fragments, size_t fragment_count)
{
    if (!fragments || fragment_count == 0) {
        printf("\nTCP Stream Reconstruction\n");
        printf("-------------------------\n");
        printf("TCP payload fragments: 0\n");
        printf("Reconstructed payload: n/a\n");
        return;
    }

    qsort(fragments,
          fragment_count,
          sizeof(struct tcp_fragment),
          compare_tcp_fragments_by_seq);

    unsigned char reconstructed[K1WI_PCAP_MAX_RECON_BYTES];
    size_t recon_len = 0;

    for (size_t i = 0; i < fragment_count; i++) {
        size_t copy_len = fragments[i].payload_len;

        if (copy_len > K1WI_PCAP_MAX_RECON_BYTES - recon_len) {
            copy_len = K1WI_PCAP_MAX_RECON_BYTES - recon_len;
        }

        for (size_t j = 0; j < copy_len; j++) {
            reconstructed[recon_len++] = fragments[i].payload[j];
        }

        if (recon_len >= K1WI_PCAP_MAX_RECON_BYTES) {
            break;
        }
    }

    char src_ip[32];
    char dst_ip[32];
    char recon_preview[K1WI_PCAP_MAX_RECON_BYTES];

    format_ipv4(fragments[0].src_ip, src_ip, sizeof(src_ip));
    format_ipv4(fragments[0].dst_ip, dst_ip, sizeof(dst_ip));

    make_ascii_preview(reconstructed,
                       recon_len,
                       recon_preview,
                       sizeof(recon_preview));

    printf("\nTCP Stream Reconstruction\n");
    printf("-------------------------\n");
    printf("Stream: %s:%u -> %s:%u\n",
           src_ip,
           (unsigned int)fragments[0].src_port,
           dst_ip,
           (unsigned int)fragments[0].dst_port);
    printf("TCP payload fragments: %zu\n", fragment_count);
    printf("Reconstructed payload bytes: %zu\n", recon_len);
    printf("Reconstructed payload by TCP sequence:\n");
    printf("%s\n", recon_preview);

    if (looks_like_base64_payload(reconstructed, recon_len)) {
        unsigned char decoded[K1WI_PCAP_MAX_RECON_BYTES];
        char decoded_preview[K1WI_PCAP_MAX_RECON_BYTES];
        size_t decoded_len = 0;

        if (decode_base64_preview(reconstructed,
                                  recon_len,
                                  decoded,
                                  sizeof(decoded),
                                  &decoded_len)) {
            make_ascii_preview(decoded,
                               decoded_len,
                               decoded_preview,
                               sizeof(decoded_preview));

            printf("\nBase64 Reconstruction\n");
            printf("---------------------\n");
            printf("Decoded bytes: %zu\n", decoded_len);
            printf("Decoded preview:\n");
            printf("%s\n", decoded_preview);
        } else {
            printf("\nBase64 Reconstruction\n");
            printf("---------------------\n");
            printf("Detected Base64-like stream, but decode failed.\n");
        }
        } else {
        printf("\nBase64 Reconstruction\n");
        printf("---------------------\n");
        printf("Reconstructed payload is not clean Base64.\n");
    }

        print_decoded_fragment_reconstruction(fragments,
                                          fragment_count,
                                          "Decoded TCP Payload Reconstruction by Sequence");

    qsort(fragments,
          fragment_count,
          sizeof(struct tcp_fragment),
          compare_tcp_fragments_by_time);

    print_decoded_fragment_reconstruction(fragments,
                                          fragment_count,
                                          "Decoded TCP Payload Reconstruction by Time");
}
    
    
int k1wi_pcap_analyze_file(const char *path, int full_mode)
{
    FILE *fp = fopen(path, "rb");

    if (!fp) {
        fprintf(stderr, "Failed to open PCAP file: %s\n", path);
        return 1;
    }

    unsigned char gh[24];

    if (fread(gh, 1, sizeof(gh), fp) != sizeof(gh)) {
        fprintf(stderr, "Failed to read PCAP global header: %s\n", path);
        fclose(fp);
        return 1;
    }

    int little_endian = 0;
    int nanosecond_precision = 0;

    /*
     * Classic PCAP magic bytes:
     * d4 c3 b2 a1 = little-endian, microsecond timestamps
     * a1 b2 c3 d4 = big-endian, microsecond timestamps
     * 4d 3c b2 a1 = little-endian, nanosecond timestamps
     * a1 b2 3c 4d = big-endian, nanosecond timestamps
     */
    if (gh[0] == 0xd4 && gh[1] == 0xc3 && gh[2] == 0xb2 && gh[3] == 0xa1) {
        little_endian = 1;
        nanosecond_precision = 0;
    } else if (gh[0] == 0xa1 && gh[1] == 0xb2 && gh[2] == 0xc3 && gh[3] == 0xd4) {
        little_endian = 0;
        nanosecond_precision = 0;
    } else if (gh[0] == 0x4d && gh[1] == 0x3c && gh[2] == 0xb2 && gh[3] == 0xa1) {
        little_endian = 1;
        nanosecond_precision = 1;
    } else if (gh[0] == 0xa1 && gh[1] == 0xb2 && gh[2] == 0x3c && gh[3] == 0x4d) {
        little_endian = 0;
        nanosecond_precision = 1;
    } else {
        fprintf(stderr,
                "Not a classic PCAP file or unsupported PCAP magic: %02x %02x %02x %02x\n",
                gh[0], gh[1], gh[2], gh[3]);
        fclose(fp);
        return 1;
    }

    uint16_t version_major = read_u16(gh + 4, little_endian);
    uint16_t version_minor = read_u16(gh + 6, little_endian);
    uint32_t snaplen = read_u32(gh + 16, little_endian);
    uint32_t network = read_u32(gh + 20, little_endian);

    uint64_t packet_count = 0;
    uint64_t total_captured_bytes = 0;
    uint64_t total_original_bytes = 0;

    uint32_t first_ts_sec = 0;
    uint32_t first_ts_frac = 0;
    uint32_t last_ts_sec = 0;
    uint32_t last_ts_frac = 0;

    int have_timestamp = 0;

    uint64_t ipv4_packets = 0;
    uint64_t tcp_packets = 0;
    uint64_t udp_packets = 0;
    uint64_t icmp_packets = 0;
    uint64_t other_ipv4_packets = 0;

    uint64_t tcp_syn_packets = 0;
    uint64_t tcp_ack_packets = 0;
    uint64_t tcp_fin_packets = 0;
    uint64_t tcp_rst_packets = 0;
    uint64_t tcp_psh_packets = 0;
    uint64_t tcp_urg_packets = 0;

    uint64_t tcp_payload_packets = 0;
    uint64_t tcp_payload_bytes = 0;
    uint64_t printable_payload_packets = 0;
    uint64_t base64_like_payload_packets = 0;
    uint64_t base64_decoded_printable_packets = 0;

    struct ip_counter source_ips[K1WI_PCAP_MAX_IPS] = {0};
    struct ip_counter destination_ips[K1WI_PCAP_MAX_IPS] = {0};

    struct port_counter tcp_source_ports[K1WI_PCAP_MAX_PORTS] = {0};
    struct port_counter tcp_destination_ports[K1WI_PCAP_MAX_PORTS] = {0};
    struct port_counter udp_source_ports[K1WI_PCAP_MAX_PORTS] = {0};
    struct port_counter udp_destination_ports[K1WI_PCAP_MAX_PORTS] = {0};

    struct tcp_fragment tcp_fragments[K1WI_PCAP_MAX_TCP_FRAGMENTS] = {0};
    size_t tcp_fragment_count = 0;

    while (1) {
        unsigned char ph[16];
        size_t got = fread(ph, 1, sizeof(ph), fp);

        if (got == 0) {
            break;
        }

        if (got != sizeof(ph)) {
            fprintf(stderr, "Truncated PCAP packet header near packet %llu\n",
                    (unsigned long long)(packet_count + 1));
            fclose(fp);
            return 1;
        }

        uint32_t ts_sec = read_u32(ph + 0, little_endian);
        uint32_t ts_frac = read_u32(ph + 4, little_endian);
        uint32_t incl_len = read_u32(ph + 8, little_endian);
        uint32_t orig_len = read_u32(ph + 12, little_endian);

        if (snaplen != 0 && incl_len > snaplen) {
            fprintf(stderr,
                    "Invalid PCAP packet length near packet %llu: %u > snaplen %u\n",
                    (unsigned long long)(packet_count + 1),
                    incl_len,
                    snaplen);
            fclose(fp);
            return 1;
        }

        unsigned char *packet_data = NULL;

    if (incl_len > 0) {
       packet_data = malloc(incl_len);

       if (!packet_data) {
           fprintf(stderr, "Out of memory reading PCAP packet %llu\n",
                (unsigned long long)(packet_count + 1));
           fclose(fp);
           return 1;
       }

              if (fread(packet_data, 1, incl_len, fp) != incl_len) {
                  fprintf(stderr, "Truncated PCAP packet data near packet %llu\n",
                          (unsigned long long)(packet_count + 1));

                  free(packet_data);
                  fclose(fp);
                  return 1;
              }
           
    }
    if (full_mode) {
        printf("Packet %llu: ts=%u.%06u captured=%u original=%u\n",
               (unsigned long long)(packet_count + 1),
               ts_sec,
               ts_frac,
               incl_len,
               orig_len);
        }

        if (!have_timestamp) {
    first_ts_sec = ts_sec;
    first_ts_frac = ts_frac;
    last_ts_sec = ts_sec;
    last_ts_frac = ts_frac;
    have_timestamp = 1;
} else {
    if (ts_sec < first_ts_sec ||
        (ts_sec == first_ts_sec && ts_frac < first_ts_frac)) {
        first_ts_sec = ts_sec;
        first_ts_frac = ts_frac;
    }

    if (ts_sec > last_ts_sec ||
        (ts_sec == last_ts_sec && ts_frac > last_ts_frac)) {
        last_ts_sec = ts_sec;
        last_ts_frac = ts_frac;
    }
}

	        if (packet_data) {
            size_t ip_offset = 0;
            size_t ip_available = 0;
            int contains_ipv4 = 0;

            if ((network == 101u || network == 228u) && incl_len >= 20u) {
                /* Raw IPv4 packet. */
                ip_offset = 0;
                contains_ipv4 = 1;
            } else if (network == 1u && incl_len >= 14u) {
                /* Ethernet II frame. */
                uint16_t ether_type = read_u16_be(packet_data + 12u);

                if (ether_type == 0x0800u && incl_len >= 14u + 20u) {
                    ip_offset = 14u;
                    contains_ipv4 = 1;
                }
            }

            if (contains_ipv4) {
                const unsigned char *ip_data = packet_data + ip_offset;

                ip_available = (size_t)incl_len - ip_offset;

                unsigned char version_ihl = ip_data[0];
                unsigned int version = (unsigned int)(version_ihl >> 4);
                unsigned int ihl =
                    (unsigned int)(version_ihl & 0x0fu) * 4u;

                if (version == 4u &&
                    ihl >= 20u &&
                    (size_t)ihl <= ip_available) {
                    uint8_t protocol = ip_data[9];
                    uint32_t src_ip = read_u32_be(ip_data + 12u);
                    uint32_t dst_ip = read_u32_be(ip_data + 16u);

                ipv4_packets++;
                add_ip_count(source_ips, K1WI_PCAP_MAX_IPS, src_ip);
                add_ip_count(destination_ips, K1WI_PCAP_MAX_IPS, dst_ip);

                                if (protocol == 1) {
                    icmp_packets++;
                
                                } else if (protocol == 6) {
                    tcp_packets++;

                    if (ip_available >= (size_t)ihl + 4u) {
                        uint16_t src_port = read_u16_be(ip_data + ihl);
                        uint16_t dst_port = read_u16_be(ip_data + ihl + 2u);

                        add_port_count(tcp_source_ports, K1WI_PCAP_MAX_PORTS, src_port);
                        add_port_count(tcp_destination_ports, K1WI_PCAP_MAX_PORTS, dst_port);

                        /*
                         * TCP payload analysis:
                         * IPv4 header starts at packet_data[0].
                         * TCP header starts at packet_data[ihl].
                         * TCP data offset is the high nibble of byte 12 in the TCP header.
                         */
                        if (ip_available >= (size_t)ihl + 20u) {
                            unsigned int tcp_header_len =
                                (unsigned int)(ip_data[ihl + 12u] >> 4) * 4u;
                            uint8_t tcp_flags = ip_data[ihl + 13u];

                            if ((tcp_flags & 0x02u) != 0u) {
                                tcp_syn_packets++;
                            }
                            if ((tcp_flags & 0x10u) != 0u) {
                                tcp_ack_packets++;
                            }
                            if ((tcp_flags & 0x01u) != 0u) {
                                tcp_fin_packets++;
                            }
                            if ((tcp_flags & 0x04u) != 0u) {
                                tcp_rst_packets++;
                            }
                            if ((tcp_flags & 0x08u) != 0u) {
                                tcp_psh_packets++;
                            }
                            if ((tcp_flags & 0x20u) != 0u) {
                                tcp_urg_packets++;
                            }

                            if (tcp_header_len >= 20u && ip_available >= (size_t)ihl + (size_t)tcp_header_len) {
                                size_t payload_offset = (size_t)ihl + (size_t)tcp_header_len;
                                size_t payload_len = ip_available - payload_offset;
                                const unsigned char *payload = ip_data + payload_offset;

                                if (payload_len > 0) {
                                    tcp_payload_packets++;
                                    tcp_payload_bytes += payload_len;

                                    
    				                                       uint32_t tcp_seq =
                                        read_u32_be(ip_data + ihl + 4u);

                                    if (full_mode) {
                                        char src_ip_text[16];
                                        char dst_ip_text[16];
                                        char flags_text[32];

                                        format_ipv4(src_ip,
                                                    src_ip_text,
                                                    sizeof(src_ip_text));
                                        format_ipv4(dst_ip,
                                                    dst_ip_text,
                                                    sizeof(dst_ip_text));
                                        format_tcp_flags(tcp_flags,
                                                         flags_text,
                                                         sizeof(flags_text));

                                        printf("  TCP %s:%u -> %s:%u "
                                               "seq=%u flags=%s payload=%zu\n",
                                               src_ip_text,
                                               (unsigned int)src_port,
                                               dst_ip_text,
                                               (unsigned int)dst_port,
                                               tcp_seq,
                                               flags_text,
                                               payload_len);
                                    }

                                    add_tcp_fragment(tcp_fragments,
                                                     &tcp_fragment_count,
                                                     K1WI_PCAP_MAX_TCP_FRAGMENTS,
                                                     src_ip,
                                                     dst_ip,
                                                     src_port,
                                                     dst_port,
                                                     tcp_seq,
                                                     packet_count + 1u,
                                                     ts_sec,
                                                     ts_frac,
                                                     payload,
                                                     payload_len);
                                    
                                    if (is_printable_payload(payload, payload_len)) {
                                        printable_payload_packets++;
                                    }

                                    if (looks_like_base64_payload(payload, payload_len)) {
                                        unsigned char decoded[K1WI_PCAP_PREVIEW_SIZE];
                                        size_t decoded_len = 0;

                                        base64_like_payload_packets++;

                                        if (decode_base64_preview(payload,
                                                                  payload_len,
                                                                  decoded,
                                                                  sizeof(decoded),
                                                                  &decoded_len) &&
                                            is_printable_payload(decoded, decoded_len)) {
                                            base64_decoded_printable_packets++;
                                        }
                                    }

                                    if (full_mode) {
                                        char preview[K1WI_PCAP_PREVIEW_SIZE];

                                        make_ascii_preview(payload,
                                                           payload_len,
                                                           preview,
                                                           sizeof(preview));

                                        printf("  TCP payload: %zu bytes\n", payload_len);
                                        printf("  Payload ASCII preview: %s\n", preview);

                                        if (looks_like_base64_payload(payload, payload_len)) {
                                            unsigned char decoded[K1WI_PCAP_PREVIEW_SIZE];
                                            char decoded_preview[K1WI_PCAP_PREVIEW_SIZE];
                                            size_t decoded_len = 0;

                                            if (decode_base64_preview(payload,
                                                                      payload_len,
                                                                      decoded,
                                                                      sizeof(decoded),
                                                                      &decoded_len)) {
                                                make_ascii_preview(decoded,
                                                                   decoded_len,
                                                                   decoded_preview,
                                                                   sizeof(decoded_preview));

                                                printf("  Base64-like payload: yes\n");
                                                printf("  Base64 decoded preview: %s\n", decoded_preview);
                                            } else {
                                                printf("  Base64-like payload: yes, decode preview failed\n");
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } else if (protocol == 17) {
                
                    udp_packets++;

                    if (ip_available >= (size_t)ihl + 4u) {
                        uint16_t src_port = read_u16_be(ip_data + ihl);
                        uint16_t dst_port = read_u16_be(ip_data + ihl + 2u);

                        add_port_count(udp_source_ports, K1WI_PCAP_MAX_PORTS, src_port);
                        add_port_count(udp_destination_ports, K1WI_PCAP_MAX_PORTS, dst_port);
                    }
                } else {
                    other_ipv4_packets++;
                }
             }
         }
      }

        packet_count++;
        total_captured_bytes += incl_len;
        total_original_bytes += orig_len;     

	free(packet_data);
    }

    fclose(fp);

    double duration = 0.0;

    if (have_timestamp) {
        double scale = nanosecond_precision ? 1000000000.0 : 1000000.0;
        double first = (double)first_ts_sec + ((double)first_ts_frac / scale);
        double last = (double)last_ts_sec + ((double)last_ts_frac / scale);
        duration = last - first;

        if (duration < 0.0) {
            duration = 0.0;
        }
    }

    double avg_packet_size = packet_count > 0
        ? (double)total_captured_bytes / (double)packet_count
        : 0.0;

    printf("\nK1Wi PCAP Summary\n");
    printf("-----------------\n");
    printf("File: %s\n", path);
    printf("Format: PCAP classic\n");
    printf("Endian: %s\n", little_endian ? "little-endian" : "big-endian");
    printf("Timestamp precision: %s\n", nanosecond_precision ? "nanoseconds" : "microseconds");
    printf("Version: %u.%u\n", version_major, version_minor);
    printf("Snap length: %u\n", snaplen);
    printf("Link type: %u (%s)\n", network, link_type_name(network));
    printf("Packets: %llu\n", (unsigned long long)packet_count);
    printf("Captured bytes: %llu\n", (unsigned long long)total_captured_bytes);
    printf("Original bytes: %llu\n", (unsigned long long)total_original_bytes);

    if (have_timestamp) {
        printf("First timestamp: %u.%06u\n", first_ts_sec, first_ts_frac);
        printf("Last timestamp: %u.%06u\n", last_ts_sec, last_ts_frac);
        printf("Duration: %.6f seconds\n", duration);
    } else {
        printf("First timestamp: n/a\n");
        printf("Last timestamp: n/a\n");
        printf("Duration: 0.000000 seconds\n");
    }

    printf("Average captured packet size: %.2f bytes\n", avg_packet_size);

    printf("\nProtocol Summary\n");
    printf("----------------\n");
    printf("IPv4 packets: %llu\n", (unsigned long long)ipv4_packets);
    printf("TCP packets: %llu\n", (unsigned long long)tcp_packets);
    printf("UDP packets: %llu\n", (unsigned long long)udp_packets);
    printf("ICMP packets: %llu\n", (unsigned long long)icmp_packets);
    printf("Other IPv4 packets: %llu\n", (unsigned long long)other_ipv4_packets);

    print_ip_table("Top Source IPs", source_ips, K1WI_PCAP_MAX_IPS);
    print_ip_table("Top Destination IPs", destination_ips, K1WI_PCAP_MAX_IPS);
	
    print_port_table("Top TCP Source Ports", tcp_source_ports, K1WI_PCAP_MAX_PORTS);
    print_port_table("Top TCP Destination Ports", tcp_destination_ports, K1WI_PCAP_MAX_PORTS);
    print_port_table("Top UDP Source Ports", udp_source_ports, K1WI_PCAP_MAX_PORTS);
    print_port_table("Top UDP Destination Ports", udp_destination_ports, K1WI_PCAP_MAX_PORTS);

    printf("\nTCP Flags Summary\n");
    printf("-----------------\n");
    printf("SYN packets: %llu\n", (unsigned long long)tcp_syn_packets);
    printf("ACK packets: %llu\n", (unsigned long long)tcp_ack_packets);
    printf("FIN packets: %llu\n", (unsigned long long)tcp_fin_packets);
    printf("RST packets: %llu\n", (unsigned long long)tcp_rst_packets);
    printf("PSH packets: %llu\n", (unsigned long long)tcp_psh_packets);
    printf("URG packets: %llu\n", (unsigned long long)tcp_urg_packets);

    printf("\nPayload Summary\n");
    printf("---------------\n");
    printf("TCP payload packets: %llu\n",
           (unsigned long long)tcp_payload_packets);
    printf("TCP payload bytes: %llu\n",
           (unsigned long long)tcp_payload_bytes);
    printf("Printable TCP payload packets: %llu\n",
           (unsigned long long)printable_payload_packets);
    printf("Base64-like TCP payload packets: %llu\n",
           (unsigned long long)base64_like_payload_packets);
    printf("Base64 decoded printable packets: %llu\n",
           (unsigned long long)base64_decoded_printable_packets);

    print_tcp_stream_reconstruction(tcp_fragments, tcp_fragment_count);
    free_tcp_fragments(tcp_fragments, tcp_fragment_count);

    return 0;
}



