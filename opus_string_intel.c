/*
 * opus_string_intel.c
 *
 * Forensic-grade string intelligence for OPUS.
 * Detects and decodes: URL, Base64, ROT13, Hex, A1Z26, hashes, UTF-8.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <stdbool.h>
#include <strings.h>   // <-- REQUIRED for strncasecmp()

#include "opus_string_intel.h"

static bool looks_like_jwt_token(const unsigned char *s, size_t len);
static bool looks_like_aws_access_key(const unsigned char *s, size_t len);
static bool looks_like_github_token(const unsigned char *s, size_t len);
static bool looks_like_ssh_public_key(const unsigned char *s, size_t len);
static bool looks_like_pem_certificate(const unsigned char *s, size_t len);
static bool looks_like_openai_key(const unsigned char *s, size_t len);
static bool looks_like_bearer_token(const unsigned char *s, size_t len);
static bool looks_like_possible_secret(const unsigned char *s, size_t len);
static bool looks_like_key_value_secret(const unsigned char *s, size_t len);
static int score_possible_secret(const unsigned char *s, size_t len);
static bool looks_like_secret_phrase(const unsigned char *s, size_t len);

static int score_key_value_secret(const unsigned char *s, size_t len);
static bool value_is_trivial_config(const unsigned char *v, size_t len);

/* ---------- Portable memmem ---------- */
static const unsigned char *memmem_portable(const unsigned char *haystack, size_t haystack_len,
                                            const unsigned char *needle, size_t needle_len)
{
    if (needle_len == 0 || haystack_len < needle_len) return NULL;

    for (size_t i = 0; i <= haystack_len - needle_len; i++) {
        if (memcmp(haystack + i, needle, needle_len) == 0) {
            return haystack + i;
        }
    }
    return NULL;
}

/* ---------- Helpers ---------- */

static size_t byte_length(const unsigned char *s) {
    return strlen((const char *)s);
}

static bool is_printable_ascii_byte(unsigned char c) {
    return (c >= 32 && c <= 126) || c == '\t' || c == '\n' || c == '\r';
}

static bool is_all_printable_ascii(const unsigned char *buf, size_t len) {
    if (len == 0) return false;
    for (size_t i = 0; i < len; i++) {
        if (!is_printable_ascii_byte(buf[i])) {
            return false;
        }
    }
    return true;
}

/* ---------- Plain URL detection ---------- */

static bool looks_like_plain_url(const unsigned char *s, size_t len)
{
    if (len < 5) return false;
    if (!is_all_printable_ascii(s, len)) return false;

    /* Prevent emails from being misclassified as URLs */
    if (memchr(s, '@', len)) {
        return false;
    }

    /* 1. Contains :// */
    if (memmem_portable(s, len,
        (const unsigned char *)"://", 3)) {
        return true;
    }

    /* 2. Starts with www. */
    if (len > 4 &&
        strncasecmp((const char *)s, "www.", 4) == 0) {
        return true;
    }

    /* 3. Ends with common TLDs */
    const char *tlds[] = {
        ".com", ".net", ".org", ".io", ".gov",
        ".edu", ".co", ".us", ".biz", ".info"
    };
    for (size_t i = 0; i < sizeof(tlds)/sizeof(tlds[0]); i++) {
        size_t tlen = strlen(tlds[i]);
        if (len > tlen &&
            strncasecmp((const char *)(s + len - tlen),
                        tlds[i], tlen) == 0) {
            return true;
        }
    }



    return false;
}

/* ---------- Email detection ---------- */

static bool looks_like_email(const unsigned char *s, size_t len)
{
    if (len < 5) return false;
    if (!is_all_printable_ascii(s, len)) return false;

    /* Must contain exactly one '@' */
    const unsigned char *at = memchr(s, '@', len);
    if (!at) return false;

    /* Ensure only one '@' */
	size_t after_at_len = len - (size_t)(at - s) - 1;

	if (memmem_portable(at + 1, after_at_len,
                        (const unsigned char *)"@", 1)) {
        return false;
    }

    /* '@' cannot be first or last */
    if (at == s || at == s + len - 1) return false;

    /* Must contain a '.' after '@' */
	size_t domain_len = (size_t)((s + len) - at);
	const unsigned char *dot = memchr(at, '.', domain_len);
    if (!dot) return false;

    /* '.' cannot be last */
    if (dot == s + len - 1) return false;

    return true;
}


static double compute_entropy(const unsigned char *buf, size_t len) {
    if (len == 0) return 0.0;

    unsigned long counts[256] = {0};
    for (size_t i = 0; i < len; i++) {
        counts[buf[i]]++;
    }

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (counts[i] == 0) continue;
        double p = (double)counts[i] / (double)len;
        entropy -= p * log2(p);
    }
    return entropy;
}

/* ---------- UTF‑8 validation ---------- */

static bool is_valid_utf8(const unsigned char *s, size_t len) {
    size_t i = 0;
    while (i < len) {
        unsigned char c = s[i];
        if (c <= 0x7F) {
            i++;
        } else if ((c & 0xE0) == 0xC0) {
            if (i + 1 >= len) return false;
            unsigned char c1 = s[i + 1];
            if ((c1 & 0xC0) != 0x80) return false;
            if (c < 0xC2) return false;
            i += 2;
        } else if ((c & 0xF0) == 0xE0) {
            if (i + 2 >= len) return false;
            unsigned char c1 = s[i + 1];
            unsigned char c2 = s[i + 2];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80) return false;
            if (c == 0xE0 && c1 < 0xA0) return false;
            if (c == 0xED && c1 >= 0xA0) return false;
            i += 3;
        } else if ((c & 0xF8) == 0xF0) {
            if (i + 3 >= len) return false;
            unsigned char c1 = s[i + 1];
            unsigned char c2 = s[i + 2];
            unsigned char c3 = s[i + 3];
            if ((c1 & 0xC0) != 0x80 || (c2 & 0xC0) != 0x80 || (c3 & 0xC0) != 0x80)
                return false;
            if (c == 0xF0 && c1 < 0x90) return false;
            if (c == 0xF4 && c1 >= 0x90) return false;
            if (c > 0xF4) return false;
            i += 4;
        } else {
            return false;
        }
    }
    return true;
}

/* ---------- Hex helpers ---------- */

static bool is_hex_string(const unsigned char *s, size_t len) {
    if (len == 0) return false;
    for (size_t i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)s[i])) return false;
    }
    return true;
}

static bool is_binary_string(const unsigned char *s, size_t len)
{
    if (len == 0) {
        return false;
    }

    for (size_t i = 0; i < len; i++) {
        if (s[i] != '0' && s[i] != '1') {
            return false;
        }
    }

    return true;
}

static bool binary_decode_string(const unsigned char *in, size_t len,
                                 unsigned char **out, size_t *out_len)
{
    if (!is_binary_string(in, len) || (len % 8) != 0) {
        return false;
    }

    size_t olen = len / 8;
    unsigned char *buf = malloc(olen + 1);
    if (!buf) {
        return false;
    }

    for (size_t i = 0; i < olen; i++) {
        unsigned char v = 0;

        for (size_t bit = 0; bit < 8; bit++) {
            v = (unsigned char)((v << 1) | (in[(i * 8) + bit] == '1'));
        }

        buf[i] = v;
    }

    buf[olen] = '\0';
    *out = buf;
    *out_len = olen;
    return true;
}

/* Decode sequences like: 0x48 0x65 0x6C 0x6C 0x6F */

static size_t hex_prefixed_decode(const unsigned char *s, size_t len,
                                  unsigned char *out, size_t out_max)
{
    size_t i = 0, o = 0;

    while (i < len && o < out_max) {
        /* Skip whitespace and commas */
        while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == ',')) {
            i++;
        }

        if (i >= len) break;

        /* Expect 0xHH */
        if (i + 3 >= len) break;
        if (!(s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X'))) break;

        i += 2;

        if (!isxdigit(s[i]) || !isxdigit(s[i+1])) break;

        unsigned char hi = s[i++];
        unsigned char lo = s[i++];

	unsigned int hi_val = (hi <= '9')
	    ? (unsigned int)(hi - '0')
	    : (unsigned int)(tolower(hi) - 'a' + 10);

	unsigned int lo_val = (lo <= '9')
	    ? (unsigned int)(lo - '0')
	    : (unsigned int)(tolower(lo) - 'a' + 10);

	unsigned char byte = (unsigned char)((hi_val << 4) | lo_val);

        out[o++] = byte;
    }

    return o;
}


/* ---------- Hex-Prefixed Byte Sequence Detection ---------- */
/* Detects patterns like: 0x48 0x65 0x6C 0x6C 0x6F */

static bool looks_like_hex_prefixed(const unsigned char *s, size_t len)
{
    size_t i = 0;
    size_t tokens = 0;

    while (i < len) {
        /* Skip whitespace and commas */
        while (i < len && (s[i] == ' ' || s[i] == '\t' || s[i] == ',')) {
            i++;
        }

        if (i >= len) break;

        /* Expect "0x" or "0X" */
        if (i + 2 >= len) return false;
        if (!(s[i] == '0' && (s[i+1] == 'x' || s[i+1] == 'X'))) {
            return false;
        }
        i += 2;

        /* Expect two hex digits */
        if (i + 1 >= len) return false;
        if (!isxdigit(s[i]) || !isxdigit(s[i+1])) {
            return false;
        }
        i += 2;

        tokens++;
    }

    /* Require at least 2 tokens to avoid false positives */
    return (tokens >= 2);
}


/* ---------- Base64 ---------- */

static int b64_index(int c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static bool looks_like_base64(const unsigned char *s, size_t len) {
    if (len < 4) return false;
    if (len % 4 != 0) return false;

    size_t pad = 0;
    if (len >= 1 && s[len - 1] == '=') pad++;
    if (len >= 2 && s[len - 2] == '=') pad++;

    for (size_t i = 0; i < len - pad; i++) {
        unsigned char c = s[i];
        if (!(
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '+' || c == '/'
        )) {
            return false;
        }
    }

    for (size_t i = 0; i < pad; i++) {
        if (s[len - 1 - i] != '=') return false;
    }

    return true;
}

static bool base64_decode(const unsigned char *in, size_t len,
                          unsigned char **out, size_t *out_len)
{
    if (!looks_like_base64(in, len)) return false;

    size_t pad = 0;
    if (len >= 1 && in[len - 1] == '=') pad++;
    if (len >= 2 && in[len - 2] == '=') pad++;

    size_t olen = (len / 4) * 3 - pad;
    unsigned char *buf = malloc(olen + 1);
    if (!buf) return false;

    size_t o = 0;
    for (size_t i = 0; i < len; i += 4) {
        int v0 = b64_index(in[i]);
        int v1 = b64_index(in[i + 1]);
        int v2 = in[i + 2] == '=' ? -1 : b64_index(in[i + 2]);
        int v3 = in[i + 3] == '=' ? -1 : b64_index(in[i + 3]);

        if (v0 < 0 || v1 < 0 || (v2 < 0 && in[i + 2] != '=') ||
            (v3 < 0 && in[i + 3] != '=')) {
            free(buf);
            return false;
        }

        unsigned int triple = (unsigned int)((v0 << 18) | (v1 << 12) |
                                             ((v2 < 0 ? 0 : v2) << 6) |
                                             (v3 < 0 ? 0 : v3));

        if (o < olen) buf[o++] = (unsigned char)((triple >> 16) & 0xFF);
        if (o < olen && in[i + 2] != '=') buf[o++] = (unsigned char)((triple >> 8) & 0xFF);
        if (o < olen && in[i + 3] != '=') buf[o++] = (unsigned char)(triple & 0xFF);
    }

    buf[olen] = '\0';
    *out = buf;
    *out_len = olen;
    return true;
}

/* ---------- ROT13 ---------- */

static bool looks_like_rot13(const unsigned char *s, size_t len) {
    if (len < 40) return false;          /* allow "Uryyb" but not tiny noise */
    if (s[0] == ' ') return false;      /* avoid leading-space islands like " OPUS" */

    if (looks_like_base64(s, len)) return false;
    if (is_hex_string(s, len)) return false;
    if (memchr(s, '%', len)) return false;

    size_t alpha = 0;
    size_t digits = 0;
    for (size_t i = 0; i < len; i++) {
        if (isalpha(s[i])) alpha++;
        else if (isdigit(s[i])) digits++;
    }

    if (digits > 0) return false;
    if ((double)alpha < (double)len * 0.7) return false;

    return true;
}

static char *rot13_decode(const unsigned char *in, size_t len) {
    char *out = malloc(len + 1);
    if (!out) return NULL;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = in[i];
        if (c >= 'A' && c <= 'Z') {
            out[i] = (char)('A' + ((c - 'A' + 13) % 26));
        } else if (c >= 'a' && c <= 'z') {
            out[i] = (char)('a' + ((c - 'a' + 13) % 26));
        } else {
            out[i] = (char)c;
        }
    }
    out[len] = '\0';
    return out;
}

/* ---------- Hex ---------- */

static bool looks_like_hex(const unsigned char *s, size_t len)
{
    if (len < 4)
        return false;

    if ((len % 2) != 0)
        return false;

    return is_hex_string(s, len);
}

static bool hex_decode(const unsigned char *in, size_t len,
                       unsigned char **out, size_t *out_len)
{
    if (!looks_like_hex(in, len)) return false;

    size_t olen = len / 2;
    unsigned char *buf = malloc(olen + 1);
    if (!buf) return false;

    for (size_t i = 0; i < olen; i++) {
        char tmp[3];
        tmp[0] = (char)in[2 * i];
        tmp[1] = (char)in[2 * i + 1];
        tmp[2] = '\0';
        buf[i] = (unsigned char)strtoul(tmp, NULL, 16);
    }

    buf[olen] = '\0';
    *out = buf;
    *out_len = olen;
    
    
    return true;
}

/* ---------- URL encoding ---------- */

static int hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}

static bool url_decode(const unsigned char *in, size_t len,
                       unsigned char **out, size_t *out_len)
{
    if (len == 0) return false;

    unsigned char *buf = malloc(len + 1);
    if (!buf) return false;

    size_t o = 0;
    bool changed = false;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = in[i];
        if (c == '%') {
            if (i + 2 >= len) {
                free(buf);
                return false;
            }
            int h1 = hex_val(in[i + 1]);
            int h2 = hex_val(in[i + 2]);
            if (h1 < 0 || h2 < 0) {
                free(buf);
                return false;
            }
            buf[o++] = (unsigned char)((h1 << 4) | h2);
            i += 2;
            changed = true;
        } else if (c == '+') {
            buf[o++] = ' ';
            changed = true;
        } else {
            buf[o++] = c;
        }
    }

    buf[o] = '\0';
    *out = buf;
    *out_len = o;

    if (!changed) {
        free(buf);
        *out = NULL;
        *out_len = 0;
        return false;
    }

    return true;
}

/* ---------- A1Z26 ---------- */

static bool looks_like_a1z26(const unsigned char *in, size_t len) {
    if (len == 0) return false;

    bool saw_digit = false;
    bool last_sep = true;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = in[i];

        if (isdigit(c)) {
            if (last_sep && c == '0') return false;
            saw_digit = true;
            last_sep = false;
        } else if (c == ',' || c == ' ') {
            if (last_sep) return false;
            last_sep = true;
        } else {
            return false;
        }
    }

    return saw_digit && !last_sep;
}

static bool a1z26_decode(const unsigned char *in, size_t len,
                         unsigned char **out, size_t *out_len)
{
    if (!looks_like_a1z26(in, len)) return false;

    char *tmp = malloc(len + 1);
    if (!tmp) return false;
    memcpy(tmp, in, len);
    tmp[len] = '\0';

    unsigned char *buf = malloc(len + 1);
    if (!buf) {
        free(tmp);
        return false;
    }

    size_t o = 0;
    char *p = tmp;

    while (*p) {
        while (*p == ' ' || *p == ',') p++;
        if (!*p) break;

        char *endp = p;
        while (isdigit((unsigned char)*endp)) endp++;

        if (endp == p) {
            free(tmp);
            free(buf);
            return false;
        }

        long v = strtol(p, NULL, 10);
        if (v < 1 || v > 26) {
            free(tmp);
            free(buf);
            return false;
        }

        buf[o++] = (unsigned char)('A' + (v - 1));
        p = endp;
        while (*p == ' ' || *p == ',') p++;
    }

    buf[o] = '\0';
    *out = buf;
    *out_len = o;

    free(tmp);
    return true;
}

/* ---------- Hash heuristics ---------- */

static bool looks_like_md5(const unsigned char *s, size_t len) {
    return (len == 32 && is_hex_string(s, len));
}

static bool looks_like_sha1(const unsigned char *s, size_t len) {
    return (len == 40 && is_hex_string(s, len));
}

static bool looks_like_sha256(const unsigned char *s, size_t len) {
    return (len == 64 && is_hex_string(s, len));
}

/* ---------- Main analyzer ---------- */

OpusStringIntelResult opus_string_intel(const char *input_cstr) {
    OpusStringIntelResult res;
    const unsigned char *input = (const unsigned char *)input_cstr;

    res.length         = byte_length(input);
    res.is_printable   = true;
    res.entropy        = compute_entropy(input, res.length);
    res.detected_type  = "Unknown";
    res.decoded_output = NULL;

    for (size_t i = 0; i < res.length; i++) {
        if (!is_printable_ascii_byte(input[i])) {
            res.is_printable = false;
            break;
        }
    }

    /* 1. URL */
    {
        unsigned char *u = NULL;
        size_t ulen = 0;
        if (url_decode(input, res.length, &u, &ulen)) {
            if (is_all_printable_ascii(u, ulen) || is_valid_utf8(u, ulen)) {
                res.detected_type = "URL encoded";
                res.decoded_output = (char *)u;
                return res;
            }
            free(u);
        }
    }

	/* 1b. Plain URL */
	if (looks_like_plain_url(input, res.length)) {
	    res.detected_type = "URL";
	    return res;
	}

	/* 1c. Email */
	if (looks_like_email(input, res.length)) {
	    res.detected_type = "Email";
	    return res;
	}
	
	/* Secret detection: Bearer Token */
	if (looks_like_bearer_token(input, res.length)) {
	    res.detected_type = "Bearer token";
	    return res;
	}
	
	/* Secret detection: OpenAI API Key */
	if (looks_like_openai_key(input, res.length)) {
	    res.detected_type = "OpenAI API key";
	    return res;
	}

	/* Secret detection: PEM Certificate */
	if (looks_like_pem_certificate(input, res.length)) {
	    res.detected_type = "PEM certificate";
	    return res;
	}

	/* Secret detection: SSH Public Key */
	if (looks_like_ssh_public_key(input, res.length)) {
	    res.detected_type = "SSH public key";
	    return res;
	}
		
	/* Secret detection: GitHub Token */
	if (looks_like_github_token(input, res.length)) {
	    res.detected_type = "GitHub token";
	    return res;
	}
		
	/* AWS Access Key */
	if (looks_like_aws_access_key(input, res.length)) {
	    res.detected_type = "AWS access key";
	    return res;
	}

        /* Secret detection: JWT Token */
	if (looks_like_jwt_token(input, res.length)) {
	    res.detected_type = "JWT token";
	    return res;
	}
	
    /* 3. Hashes — MUST override hex, ROT13, and UTF‑8 */
    if (looks_like_md5(input, res.length)) {
        res.detected_type = "MD5 hash";
        return res;
    }
    if (looks_like_sha1(input, res.length)) {
        res.detected_type = "SHA1 hash";
        return res;
    }
    if (looks_like_sha256(input, res.length)) {
        res.detected_type = "SHA256 hash";
        return res;
    }

    /* 4. ROT13 */
    if (looks_like_rot13(input, res.length)) {
        char *out = rot13_decode(input, res.length);
        if (out) {
            res.detected_type = "ROT13";
            res.decoded_output = out;
            return res;
        }
    }




    /* 4a. Binary strings must be handled before hex/shifted-hex.
     * A long 0/1 string is also technically hex, but binary is the
     * more specific interpretation. If not byte-aligned, report that
     * instead of falling through to shifted hex.
     */
    if (is_binary_string(input, res.length)) {
        unsigned char *bin = NULL;
        size_t binlen = 0;

        if (binary_decode_string(input, res.length, &bin, &binlen)) {
            res.detected_type = "Binary";
            res.decoded_output = (char *)bin;
            return res;
        }

        res.detected_type = "Binary-like string (not byte-aligned)";
        return res;
    }

/* 4b. Hex-Prefixed Byte Sequences: 0x48 0x65 0x6C ... */
if (looks_like_hex_prefixed(input, res.length)) {
    unsigned char *buf = malloc(res.length);
    if (buf) {
        size_t outlen = hex_prefixed_decode(input, res.length, buf, res.length);
        if (outlen > 0) {
            res.detected_type = "Hex-Prefixed Bytes";
            res.decoded_output = (char *)buf;  // raw bytes OK
            return res;
        }
        free(buf);
    }
}

   
	/* 5. Hex */
	{
	    unsigned char *h = NULL;
	    size_t hlen = 0;

	    if (hex_decode(input, res.length, &h, &hlen)) {
		if (is_all_printable_ascii(h, hlen) || is_valid_utf8(h, hlen)) {

		    if (memmem_portable(
		            h, hlen,
		            (const unsigned char *)"BEGIN PRIVATE KEY",
		            strlen("BEGIN PRIVATE KEY"))) {
		        res.detected_type = "Hex encoded private key";
		    } else {
		        res.detected_type = "Hex";
		    }

		    res.decoded_output = (char *)h;
		    return res;
		}

		free(h);
		return res;
	    }
	}
	
	/* 5b. Shifted Hex: tolerate one junk prefix character */
	if (res.length > 33 && ((res.length - 1) % 2) == 0) {
	    unsigned char *h = NULL;
	    size_t hlen = 0;

	    if (hex_decode(input + 1, res.length - 1, &h, &hlen)) {
		if (is_all_printable_ascii(h, hlen) || is_valid_utf8(h, hlen)) {

		    if (memmem_portable(
		            h, hlen,
		            (const unsigned char *)"BEGIN PRIVATE KEY",
		            strlen("BEGIN PRIVATE KEY"))) {
		        res.detected_type = "Shifted hex encoded private key";
		    } else {
		        res.detected_type = "Shifted hex";
		    }

		    res.decoded_output = (char *)h;
		    return res;
		}

		free(h);
	    }
	}

/* 2. Base64 */
{
    unsigned char *b = NULL;
    size_t blen = 0;
    if (base64_decode(input, res.length, &b, &blen)) {
        if (is_all_printable_ascii(b, blen) || is_valid_utf8(b, blen)) {
            res.detected_type = "Base64";
            res.decoded_output = (char *)b;
            return res;
        }
        free(b);
        return res;
    }
}

	/* Key/value secret detection */
	if (looks_like_key_value_secret(input, res.length)) {
	    res.detected_type = "Key/value secret";
	    res.secret_score = score_key_value_secret(input, res.length);
	    return res;
	}
	/* Secret phrase/header detection */
	if (looks_like_secret_phrase(input, res.length)) {
	    res.detected_type = "Secret phrase";
	    res.secret_score = score_key_value_secret(input, res.length);
	    return res;
	}

	/* Heuristic secret detection */
	if (looks_like_possible_secret(input, res.length)) {
	    res.detected_type = "Possible credential";
	    res.secret_score = score_possible_secret(input, res.length);
	    return res;
	}

    /* 2. Base64 */
    {
        unsigned char *b = NULL;
        size_t blen = 0;
        if (base64_decode(input, res.length, &b, &blen)) {
            if (is_all_printable_ascii(b, blen) || is_valid_utf8(b, blen)) {
                res.detected_type = "Base64";
                res.decoded_output = (char *)b;
                return res;
            }
            free(b);
            return res;
        }
    }


    /* 6. A1Z26 */
    {
        unsigned char *a = NULL;
        size_t alen = 0;
        if (a1z26_decode(input, res.length, &a, &alen)) {
            res.detected_type = "A1Z26";
            res.decoded_output = (char *)a;
            return res;
        }
    }

    /* 7. Escaped \x sequences */
    if (res.length >= 2 &&
        memmem_portable(input, res.length, (const unsigned char *)"\\x", 2)) {
        res.detected_type = "Unknown";
        return res;
    }



    /* 8. UTF‑8 fallback */
    if (is_valid_utf8(input, res.length)) {
        res.detected_type = "UTF‑8 text";
        return res;
    }

    return res;
}
static double string_entropy_local(const unsigned char *s, size_t len)
{
    if (!s || len == 0)
        return 0.0;

    unsigned int freq[256] = {0};

    for (size_t i = 0; i < len; i++)
        freq[s[i]]++;

    double entropy = 0.0;

    for (int i = 0; i < 256; i++) {
        if (freq[i] == 0)
            continue;

        double p = (double)freq[i] / (double)len;
        entropy -= p * log2(p);
    }

    return entropy;
}
static bool is_base64url_char(unsigned char c)
{
    return isalnum((unsigned char)c) || c == '-' || c == '_';
}
static bool looks_like_bearer_token(const unsigned char *s, size_t len)
{
    const char *prefix1 = "Bearer ";
    const char *prefix2 = "Authorization: Bearer ";

    if (!s || len < 20)
        return false;

    if (strncmp((const char *)s, prefix1, strlen(prefix1)) == 0)
        return true;

    if (strncmp((const char *)s, prefix2, strlen(prefix2)) == 0)
        return true;

    return false;
}
static bool looks_like_openai_key(const unsigned char *s, size_t len)
{
    if (!s || len < 20)
        return false;

    if (strncmp((const char *)s, "sk-proj-", 8) == 0)
        return true;

    if (strncmp((const char *)s, "sk-", 3) == 0)
        return true;

    return false;
}

static bool contains_case_insensitive(const unsigned char *s,
                                      size_t len,
                                      const char *needle)
{
    size_t nlen = strlen(needle);

    if (!s || !needle || nlen == 0 || len < nlen)
        return false;

    for (size_t i = 0; i + nlen <= len; i++) {
        size_t j = 0;

        while (j < nlen &&
               tolower((unsigned char)s[i + j]) ==
               tolower((unsigned char)needle[j])) {
            j++;
        }

        if (j == nlen)
            return true;
    }

    return false;
}

static bool looks_like_secret_phrase(const unsigned char *s, size_t len)
{
    if (!s || len < 10)
        return false;

    const char *phrases[] = {
        "authorization: bearer ",
        "x-api-key:",
        "x-api-key ",
        "api-key:",
        "api-key ",
        "token ",
        "password ",
        "secret ",
        "bearer "
    };

    for (size_t i = 0; i < sizeof(phrases) / sizeof(phrases[0]); i++) {
        if (contains_case_insensitive(s, len, phrases[i])) {
            return true;
        }
    }

    return false;
}
static int score_possible_secret(const unsigned char *s, size_t len)
{
    if (!s || len == 0)
        return 0;

    int score = 0;
    int has_upper = 0;
    int has_lower = 0;
    int has_digit = 0;
    int has_symbol = 0;
    int bad_chars = 0;

    for (size_t i = 0; i < len; i++) {
        unsigned char c = s[i];

        if (isupper(c)) has_upper = 1;
        else if (islower(c)) has_lower = 1;
        else if (isdigit(c)) has_digit = 1;
        else if (c == '_' || c == '-' || c == '=' || c == '.' || c == '/')
            has_symbol = 1;
        else
            bad_chars++;
    }

    int classes = 0;

    if (has_upper) classes++;
    if (has_lower) classes++;
    if (has_digit) classes++;
    if (has_symbol) classes++;

    if (classes < 3)
        return 0;

    double ent = string_entropy_local(s, len);

    if (len >= 24) score += 15;
    if (len >= 32) score += 10;
    if (len >= 48) score += 10;

    if (ent >= 3.5) score += 10;
    if (ent >= 4.0) score += 15;
    if (ent >= 4.5) score += 15;

    if (has_upper) score += 8;
    if (has_lower) score += 8;
    if (has_digit) score += 8;
    if (has_symbol) score += 8;

    if (bad_chars > 2)
        score -= 25;

    if (score < 0) score = 0;
    if (score > 100) score = 100;

    return score;
}
static int score_key_value_secret(const unsigned char *s, size_t len)
{
    if (!s || len == 0)
        return 0;

    int score = 55;

    if (contains_case_insensitive(s, len, "client_secret"))
        score += 25;
    else if (contains_case_insensitive(s, len, "private_key"))
        score += 25;
    else if (contains_case_insensitive(s, len, "api_key") ||
             contains_case_insensitive(s, len, "apikey"))
        score += 20;
    else if (contains_case_insensitive(s, len, "access_token") ||
             contains_case_insensitive(s, len, "auth_token"))
        score += 20;
    else if (contains_case_insensitive(s, len, "secret"))
        score += 15;
    else if (contains_case_insensitive(s, len, "token"))
        score += 15;
    else if (contains_case_insensitive(s, len, "password") ||
             contains_case_insensitive(s, len, "passwd") ||
             contains_case_insensitive(s, len, "pwd"))
        score += 10;

    double ent = string_entropy_local(s, len);

    if (len >= 20) score += 5;
    if (len >= 32) score += 5;

    if (ent >= 3.5) score += 5;
    if (ent >= 4.5) score += 10;
    if (ent >= 5.0) score += 10;

    if (score > 100)
        score = 100;

    return score;
}
static bool looks_like_possible_secret(const unsigned char *s,
                                       size_t len)
{
    return score_possible_secret(s, len) >= 60;
}

static bool starts_with_secret_key(const unsigned char *s, size_t len,
                                   const char *key)
{
    size_t klen = strlen(key);

    if (len < klen)
        return false;

    for (size_t i = 0; i < klen; i++) {
        if (tolower((unsigned char)s[i]) !=
            tolower((unsigned char)key[i])) {
            return false;
        }
    }

    return true;
}

static bool looks_like_key_value_secret(const unsigned char *s, size_t len)
{
    if (!s || len < 8)
        return false;

    const char *keys[] = {
        "password",
        "passwd",
        "pwd",
        "secret",
        "api_key",
        "apikey",
        "access_key",
        "access_token",
        "auth_token",
        "token",
        "bearer",
        "client_secret",
        "private_key"
    };

    const unsigned char *eq = memchr(s, '=', len);

    if (!eq) {
        eq = memchr(s, ':', len);
    }

    if (!eq)
        return false;

    size_t key_len = (size_t)(eq - s);
    const unsigned char *value = eq + 1;
    size_t value_len = len - key_len - 1;

    if (key_len == 0 || value_len < 1)
        return false;

    while (value_len > 0 && isspace((unsigned char)*value)) {
        value++;
        value_len--;
    }

    if (value_len < 6)
        return false;

    if (value_is_trivial_config(value, value_len))
        return false;

    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
        if (starts_with_secret_key(s, key_len, keys[i])) {
            return true;
        }
    }

    return false;
}
static bool looks_like_pem_certificate(const unsigned char *s, size_t len)
{
    if (!s || len < 25)
        return false;

    if (strncmp((const char *)s, "-----BEGIN CERTIFICATE-----", 27) == 0)
        return true;

    if (strncmp((const char *)s, "-----END CERTIFICATE-----", 25) == 0)
        return true;

    return false;
}
static bool looks_like_ssh_public_key(const unsigned char *s, size_t len)
{
    if (!s || len < 20)
        return false;

    if (strncmp((const char *)s, "ssh-rsa ", 8) == 0)
        return true;

    if (strncmp((const char *)s, "ssh-ed25519 ", 12) == 0)
        return true;

    if (strncmp((const char *)s, "ecdsa-sha2-", 11) == 0)
        return true;

    return false;
}

static bool looks_like_github_token(const unsigned char *s, size_t len)
{
    if (!s || len < 20)
        return false;

    if (len >= 40 &&
        strncmp((const char *)s, "ghp_", 4) == 0)
        return true;

    if (len >= 20 &&
        strncmp((const char *)s, "github_pat_", 11) == 0)
        return true;

    return false;
}
static bool looks_like_jwt_token(const unsigned char *s, size_t len)
{
    if (!s || len < 20)
        return false;

    int dots = 0;
    size_t part_len = 0;

    for (size_t i = 0; i < len; i++) {
        if (s[i] == '.') {
            if (part_len == 0)
                return false;

            dots++;
            part_len = 0;

            if (dots > 2)
                return false;
        }
        else if (!is_base64url_char(s[i])) {
            return false;
        }
        else {
            part_len++;
        }
    }

    if (dots != 2 || part_len == 0)
        return false;

    return true;
}
static bool looks_like_aws_access_key(const unsigned char *s, size_t len)
{
    if (len != 20)
        return false;

    if (strncmp((const char *)s, "AKIA", 4) != 0 &&
        strncmp((const char *)s, "ASIA", 4) != 0)
        return false;

   for (size_t i = 4; i < len; i++) {
    if (!isupper((unsigned char)s[i]) &&
        !isdigit((unsigned char)s[i]))
        return false;
    }

    return true;
}
static bool value_is_trivial_config(const unsigned char *v, size_t len)
{
    if (!v || len == 0)
        return true;

    while (len > 0 && isspace((unsigned char)*v)) {
        v++;
        len--;
    }

    while (len > 0 && isspace((unsigned char)v[len - 1])) {
        len--;
    }

    if (len == 0)
        return true;

    const char *trivial[] = {
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "enabled",
        "disabled",
        "enable",
        "disable",
        "null",
        "none",
        "nil",
        "0",
        "1"
    };

    for (size_t i = 0; i < sizeof(trivial) / sizeof(trivial[0]); i++) {
        size_t tlen = strlen(trivial[i]);

        if (len == tlen) {
            bool match = true;

            for (size_t j = 0; j < len; j++) {
                if (tolower((unsigned char)v[j]) !=
                    tolower((unsigned char)trivial[i][j])) {
                    match = false;
                    break;
                }
            }

            if (match)
                return true;
        }
    }

    int all_digits = 1;

    for (size_t i = 0; i < len; i++) {
        if (!isdigit((unsigned char)v[i])) {
            all_digits = 0;
            break;
        }
    }

    if (all_digits && len <= 4)
        return true;

    return false;
}
void opus_string_intel_print(const OpusStringIntelResult *r)
{
    if (!r) return;

    printf("  Length: %zu\n", r->length);
    printf("  Printable: %s\n", r->is_printable ? "yes" : "no");
    printf("  Entropy: %.4f\n", r->entropy);

    if (r->detected_type)
        printf("  Detected Type: %s\n", r->detected_type);

    if (r->decoded_output)
        printf("  Decoded Output:\n%s\n", r->decoded_output);
}

