#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "embedded_sig.h"
#include "cipher_io.h"

typedef struct sig_pattern {
    const unsigned char *magic;
    size_t magic_len;
    const char *type;
} sig_pattern_t;

static const unsigned char SIG_JPEG[]   = {0xFF, 0xD8, 0xFF};
static const unsigned char SIG_PNG[]    = {0x89, 'P', 'N', 'G'};
static const unsigned char SIG_ZIP[]    = {'P', 'K', 0x03, 0x04};
static const unsigned char SIG_PDF[]    = {'%', 'P', 'D', 'F', '-'};
static const unsigned char SIG_EXE[]    = {'M', 'Z'};
static const unsigned char SIG_RAR[]    = {'R', 'a', 'r', '!'};
static const unsigned char SIG_7Z[]     = {0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C};
static const unsigned char SIG_SQLITE[] = {'S','Q','L','i','t','e',' ','f','o','r','m','a','t',' ','3'};

static const unsigned char SIG_ELF[]    = {0x7F, 'E', 'L', 'F'};
static const unsigned char SIG_GIF87[]  = {'G', 'I', 'F', '8', '7', 'a'};
static const unsigned char SIG_GIF89[]  = {'G', 'I', 'F', '8', '9', 'a'};
static const unsigned char SIG_GZIP[]   = {0x1F, 0x8B};


/*Mach-O signatures */
static const unsigned char SIG_MACHO_32_BE[] = {0xFE, 0xED, 0xFA, 0xCE};
static const unsigned char SIG_MACHO_64_BE[] = {0xFE, 0xED, 0xFA, 0xCF};
static const unsigned char SIG_MACHO_32_LE[] = {0xCE, 0xFA, 0xED, 0xFE};
static const unsigned char SIG_MACHO_64_LE[] = {0xCF, 0xFA, 0xED, 0xFE};
static const unsigned char SIG_MACHO_FAT_BE[] = {0xCA, 0xFE, 0xBA, 0xBE};
static const unsigned char SIG_MACHO_FAT_LE[] = {0xBE, 0xBA, 0xFE, 0xCA};

/* Java Script signatures */

static const unsigned char SIG_PCAP_BE[]    = {0xA1, 0xB2, 0xC3, 0xD4};
static const unsigned char SIG_PCAP_LE[]    = {0xD4, 0xC3, 0xB2, 0xA1};
static const unsigned char SIG_PCAP_NS_BE[] = {0xA1, 0xB2, 0x3C, 0x4D};
static const unsigned char SIG_PCAP_NS_LE[] = {0x4D, 0x3C, 0xB2, 0xA1};

static const sig_pattern_t patterns[] = {
    { SIG_JPEG,   sizeof(SIG_JPEG),   "JPEG image" },
    { SIG_PNG,    sizeof(SIG_PNG),    "PNG image" },
    { SIG_ZIP,    sizeof(SIG_ZIP),    "ZIP archive" },
    { SIG_PDF,    sizeof(SIG_PDF),    "PDF document" },
    { SIG_EXE,    sizeof(SIG_EXE),    "Windows executable" },
    { SIG_RAR,    sizeof(SIG_RAR),    "RAR archive" },
    { SIG_7Z,     sizeof(SIG_7Z),     "7-Zip archive" },
    { SIG_SQLITE, sizeof(SIG_SQLITE), "SQLite database" },
    { SIG_ELF,   sizeof(SIG_ELF),   "ELF executable" },
    { SIG_GIF87, sizeof(SIG_GIF87), "GIF image" },
    { SIG_GIF89, sizeof(SIG_GIF89), "GIF image" },
    { SIG_GZIP,  sizeof(SIG_GZIP),  "GZIP archive" },
    { SIG_MACHO_32_BE,  sizeof(SIG_MACHO_32_BE),  "Mach-O executable" },
    { SIG_MACHO_32_BE,  sizeof(SIG_MACHO_32_BE),  "Mach-O executable" },
    { SIG_MACHO_64_BE,  sizeof(SIG_MACHO_64_BE),  "Mach-O executable" },
    { SIG_MACHO_32_LE,  sizeof(SIG_MACHO_32_LE),  "Mach-O executable" },
    { SIG_MACHO_64_LE,  sizeof(SIG_MACHO_64_LE),  "Mach-O executable" },
    { SIG_MACHO_FAT_BE, sizeof(SIG_MACHO_FAT_BE), "Mach-O universal binary" },
    { SIG_MACHO_FAT_LE, sizeof(SIG_MACHO_FAT_LE), "Mach-O universal binary" },


    { SIG_PCAP_BE,    sizeof(SIG_PCAP_BE),    "PCAP capture" },
    { SIG_PCAP_LE,    sizeof(SIG_PCAP_LE),    "PCAP capture" },
    { SIG_PCAP_NS_BE, sizeof(SIG_PCAP_NS_BE), "PCAP-ng/ns capture" },
    { SIG_PCAP_NS_LE, sizeof(SIG_PCAP_NS_LE), "PCAP-ng/ns capture" },

};

static void add_hit(embedded_sig_report_t *report, size_t offset, const char *type)
{
    if (!report || !type)
        return;

    if (report->count >= 32)
        return;

    report->hits[report->count].offset = offset;
    report->hits[report->count].type = type;
    report->count++;
}

static int is_bmp_at(const uint8_t *buf, size_t size, size_t off)
{
    if (!buf || off + 14 > size)
        return 0;

    if (memcmp(buf + off, "BM", 2) != 0)
        return 0;

    uint32_t declared_size =
        (uint32_t)buf[off + 2] |
        ((uint32_t)buf[off + 3] << 8) |
        ((uint32_t)buf[off + 4] << 16) |
        ((uint32_t)buf[off + 5] << 24);

    uint32_t pixel_offset =
        (uint32_t)buf[off + 10] |
        ((uint32_t)buf[off + 11] << 8) |
        ((uint32_t)buf[off + 12] << 16) |
        ((uint32_t)buf[off + 13] << 24);

    if (declared_size < 14)
        return 0;

    if (declared_size > size - off)
        return 0;

    if (pixel_offset < 14)
        return 0;

    if (pixel_offset > declared_size)
        return 0;

    return 1;
}

static int is_tar_header_at(const uint8_t *buf, size_t size, size_t off)
{
    if (!buf)
        return 0;

    if (off + 262 > size)
        return 0;

    return memcmp(buf + off + 257,
                  "ustar",
                  5) == 0;
}
static int is_java_class_at(const uint8_t *buf, size_t size, size_t off)
{
    if (!buf || off + 8 > size) {
        return 0;
    }

    if (memcmp(buf + off, "\xCA\xFE\xBA\xBE", 4) != 0) {
        return 0;
    }

    uint16_t major =
        (uint16_t)(((uint16_t)buf[off + 6] << 8) |
                   (uint16_t)buf[off + 7]);

    /* Java major versions:
       45 = Java 1.1
       52 = Java 8
       61 = Java 17
       65 = Java 21
    */

    return (major >= 45 && major <= 65);
}

static int is_webp_at(const uint8_t *buf, size_t size, size_t off)
{
    if (!buf)
        return 0;

    if (off + 12 > size)
        return 0;

    return memcmp(buf + off, "RIFF", 4) == 0 &&
           memcmp(buf + off + 8, "WEBP", 4) == 0;
}
int embedded_sig_scan_file(const char *path, embedded_sig_report_t *report)
{
    if (!path || !report)
        return -1;

    memset(report, 0, sizeof(*report));

    size_t size = 0;
    uint8_t *buf = opus_load_entire_file(path, &size);
    if (!buf)
        return -1;

for (size_t i = 0; i < size; i++) {

    if (is_webp_at(buf, size, i)) {
        add_hit(report, i, "WebP image");
    }

    if ((i % 512) == 0 && is_tar_header_at(buf, size, i)) {
	add_hit(report, i, "TAR archive");
    }
  
    if (is_bmp_at(buf, size, i)) {
    	add_hit(report, i, "BMP image");
    }   
    if (is_java_class_at(buf, size, i)) {
    add_hit(report, i, "Java class file");
    
    continue;
    }
	    for (size_t p = 0;
		 p < sizeof(patterns) / sizeof(patterns[0]);
		 p++) {

		if (i + patterns[p].magic_len <= size &&
		    memcmp(buf + i,
		           patterns[p].magic,
		           patterns[p].magic_len) == 0) {

		    add_hit(report, i, patterns[p].type);
		}
	    }
	}

    free(buf);
    return 0;
}
