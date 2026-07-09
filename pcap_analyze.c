#include "pcap_analyze.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

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

struct ip_counter {
    uint32_t ip;
    uint64_t count;
};

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

struct ip_counter source_ips[K1WI_PCAP_MAX_IPS] = {0};
struct ip_counter destination_ips[K1WI_PCAP_MAX_IPS] = {0};

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
           if (full_mode) {
               printf("Packet %llu: ts=%u.%06u captured=%u original=%u\n",
                       (unsigned long long)packet_count, ts_sec, ts_frac, incl_len, orig_len);
           }
                    
           free(packet_data);
           fclose(fp);
           return 1;
       }
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

	if (packet_data && incl_len >= 20 && (network == 228 || network == 101)) {
            unsigned char version_ihl = packet_data[0];
    	    unsigned int version = (unsigned int)(version_ihl >> 4);
            unsigned int ihl = (unsigned int)(version_ihl & 0x0fu) * 4u;

            if (version == 4 && ihl >= 20u && ihl <= incl_len) {
                uint8_t protocol = packet_data[9];
                uint32_t src_ip = read_u32_be(packet_data + 12);
                uint32_t dst_ip = read_u32_be(packet_data + 16);

                ipv4_packets++;
                add_ip_count(source_ips, K1WI_PCAP_MAX_IPS, src_ip);
                add_ip_count(destination_ips, K1WI_PCAP_MAX_IPS, dst_ip);

                if (protocol == 1) {
                    icmp_packets++;
                } else if (protocol == 6) {
                    tcp_packets++;
                } else if (protocol == 17) {
                    udp_packets++;
                } else {
                    other_ipv4_packets++;
             }
         }
      }

        packet_count++;
        total_captured_bytes += incl_len;
        total_original_bytes += orig_len;

        if (full_mode) {
            printf("Packet %llu: ts=%u.%06u captured=%u original=%u\n",
                   (unsigned long long)packet_count,
                   ts_sec,
                   ts_frac,
                   incl_len,
                   orig_len);
        }
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

    return 0;
}
