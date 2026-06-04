#include "md5.h"
#include <string.h>
#include <stdio.h>

/* MD5 basic functions and constants are from RFC 1321 */

#define F(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~(z))))

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define FF(a, b, c, d, x, s, ac) { \
    (a) += F((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define GG(a, b, c, d, x, s, ac) { \
    (a) += G((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define HH(a, b, c, d, x, s, ac) { \
    (a) += H((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}
#define II(a, b, c, d, x, s, ac) { \
    (a) += I((b), (c), (d)) + (x) + (uint32_t)(ac); \
    (a) = ROTATE_LEFT((a), (s)); \
    (a) += (b); \
}

static void opus_md5_transform(uint32_t state[4], const uint8_t block[64]);
static void encode_le(uint8_t *output, const uint32_t *input, size_t len);


/* ----------------------------------------------------------------------
 * Core MD5 engine (your original implementation)
 * ---------------------------------------------------------------------- */

void opus_md5_init(OPUS_MD5_CTX *ctx) {
    ctx->count[0] = ctx->count[1] = 0;
    ctx->state[0] = 0x67452301U;
    ctx->state[1] = 0xefcdab89U;
    ctx->state[2] = 0x98badcfeU;
    ctx->state[3] = 0x10325476U;
}

void opus_md5_update(OPUS_MD5_CTX *ctx, const void *data, size_t len) {
    const uint8_t *input = (const uint8_t *)data;
    size_t index = (ctx->count[0] >> 3) & 0x3F;

    uint32_t inputBitsLow = (uint32_t)(len << 3);
    ctx->count[0] += inputBitsLow;
    if (ctx->count[0] < inputBitsLow)
        ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);

    size_t partLen = 64 - index;
    size_t i = 0;

    if (len >= partLen) {
        memcpy(&ctx->buffer[index], input, partLen);
        opus_md5_transform(ctx->state, ctx->buffer);
        for (i = partLen; i + 63 < len; i += 64)
            opus_md5_transform(ctx->state, &input[i]);
        index = 0;
    }

    if (i < len)
        memcpy(&ctx->buffer[index], &input[i], len - i);
}

void opus_md5_final(uint8_t digest[16], OPUS_MD5_CTX *ctx) {
    static const uint8_t PADDING[64] = { 0x80 };
    uint8_t bits[8];
    uint32_t count_le[2];

    count_le[0] = ctx->count[0];
    count_le[1] = ctx->count[1];
    encode_le(bits, count_le, 8);

    size_t index = (ctx->count[0] >> 3) & 0x3F;
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);
    opus_md5_update(ctx, PADDING, padLen);

    opus_md5_update(ctx, bits, 8);

    encode_le(digest, ctx->state, 16);

    memset(ctx, 0, sizeof(*ctx));
}

void opus_md5(const void *data, size_t len, uint8_t digest[16]) {
    OPUS_MD5_CTX ctx;
    opus_md5_init(&ctx);
    opus_md5_update(&ctx, data, len);
    opus_md5_final(digest, &ctx);
}

/* ----------------------------------------------------------------------
 * Wrapper helpers for TUI and CLI
 * ---------------------------------------------------------------------- */

static void opus_md5_digest_to_hex(const uint8_t digest[16], char out_hex[33]) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out_hex[i*2]     = hex[(digest[i] >> 4) & 0xF];
        out_hex[i*2 + 1] = hex[digest[i] & 0xF];
    }
    out_hex[32] = '\0';
}

bool opus_md5_file(const char *path, char out_hex[33]) {
    if (!path || !out_hex)
        return false;

    FILE *f = fopen(path, "rb");
    if (!f)
        return false;

    OPUS_MD5_CTX ctx;
    opus_md5_init(&ctx);

    uint8_t buf[8192];
    size_t n;

    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
        opus_md5_update(&ctx, buf, n);

    fclose(f);

    uint8_t digest[16];
    opus_md5_final(digest, &ctx);
    opus_md5_digest_to_hex(digest, out_hex);

    return true;
}

bool opus_md5_buffer(const void *data, size_t len, char out_hex[33]) {
    if (!data || !out_hex)
        return false;

    OPUS_MD5_CTX ctx;
    opus_md5_init(&ctx);
    opus_md5_update(&ctx, data, len);

    uint8_t digest[16];
    opus_md5_final(digest, &ctx);
    opus_md5_digest_to_hex(digest, out_hex);

    return true;
}

bool opus_md5_string(const char *s, char out_hex[33]) {
    if (!s || !out_hex)
        return false;

    return opus_md5_buffer(s, strlen(s), out_hex);
}
static void encode_le(uint8_t *output, const uint32_t *input, size_t len)
{
    for (size_t i = 0; i < len / 4; i++) {
        output[i*4 + 0] = (uint8_t)(input[i] & 0xff);
        output[i*4 + 1] = (uint8_t)((input[i] >> 8) & 0xff);
        output[i*4 + 2] = (uint8_t)((input[i] >> 16) & 0xff);
        output[i*4 + 3] = (uint8_t)((input[i] >> 24) & 0xff);
    }
}
static void opus_md5_transform(uint32_t state[4], const uint8_t block[64])
{
    uint32_t a = state[0];
    uint32_t b = state[1];
    uint32_t c = state[2];
    uint32_t d = state[3];
    uint32_t x[16];

    for (int i = 0; i < 16; i++) {
        x[i] =  (uint32_t)block[i*4 + 0]
             | ((uint32_t)block[i*4 + 1] << 8)
             | ((uint32_t)block[i*4 + 2] << 16)
             | ((uint32_t)block[i*4 + 3] << 24);
    }


 
    #define STEP(f,a,b,c,d,xk,s,ti) \
        a += f(b,c,d) + xk + ti; \
        a = b + ROTATE_LEFT(a, s);

    /* Round 1 */
    STEP(F,a,b,c,d,x[ 0], 7,0xd76aa478);
    STEP(F,d,a,b,c,x[ 1],12,0xe8c7b756);
    STEP(F,c,d,a,b,x[ 2],17,0x242070db);
    STEP(F,b,c,d,a,x[ 3],22,0xc1bdceee);
    STEP(F,a,b,c,d,x[ 4], 7,0xf57c0faf);
    STEP(F,d,a,b,c,x[ 5],12,0x4787c62a);
    STEP(F,c,d,a,b,x[ 6],17,0xa8304613);
    STEP(F,b,c,d,a,x[ 7],22,0xfd469501);
    STEP(F,a,b,c,d,x[ 8], 7,0x698098d8);
    STEP(F,d,a,b,c,x[ 9],12,0x8b44f7af);
    STEP(F,c,d,a,b,x[10],17,0xffff5bb1);
    STEP(F,b,c,d,a,x[11],22,0x895cd7be);
    STEP(F,a,b,c,d,x[12], 7,0x6b901122);
    STEP(F,d,a,b,c,x[13],12,0xfd987193);
    STEP(F,c,d,a,b,x[14],17,0xa679438e);
    STEP(F,b,c,d,a,x[15],22,0x49b40821);

    /* Round 2 */
    STEP(G,a,b,c,d,x[ 1], 5,0xf61e2562);
    STEP(G,d,a,b,c,x[ 6], 9,0xc040b340);
    STEP(G,c,d,a,b,x[11],14,0x265e5a51);
    STEP(G,b,c,d,a,x[ 0],20,0xe9b6c7aa);
    STEP(G,a,b,c,d,x[ 5], 5,0xd62f105d);
    STEP(G,d,a,b,c,x[10], 9,0x02441453);
    STEP(G,c,d,a,b,x[15],14,0xd8a1e681);
    STEP(G,b,c,d,a,x[ 4],20,0xe7d3fbc8);
    STEP(G,a,b,c,d,x[ 9], 5,0x21e1cde6);
    STEP(G,d,a,b,c,x[14], 9,0xc33707d6);
    STEP(G,c,d,a,b,x[ 3],14,0xf4d50d87);
    STEP(G,b,c,d,a,x[ 8],20,0x455a14ed);
    STEP(G,a,b,c,d,x[13], 5,0xa9e3e905);
    STEP(G,d,a,b,c,x[ 2], 9,0xfcefa3f8);
    STEP(G,c,d,a,b,x[ 7],14,0x676f02d9);
    STEP(G,b,c,d,a,x[12],20,0x8d2a4c8a);

    /* Round 3 */
    STEP(H,a,b,c,d,x[ 5], 4,0xfffa3942);
    STEP(H,d,a,b,c,x[ 8],11,0x8771f681);
    STEP(H,c,d,a,b,x[11],16,0x6d9d6122);
    STEP(H,b,c,d,a,x[14],23,0xfde5380c);
    STEP(H,a,b,c,d,x[ 1], 4,0xa4beea44);
    STEP(H,d,a,b,c,x[ 4],11,0x4bdecfa9);
    STEP(H,c,d,a,b,x[ 7],16,0xf6bb4b60);
    STEP(H,b,c,d,a,x[10],23,0xbebfbc70);
    STEP(H,a,b,c,d,x[13], 4,0x289b7ec6);
    STEP(H,d,a,b,c,x[ 0],11,0xeaa127fa);
    STEP(H,c,d,a,b,x[ 3],16,0xd4ef3085);
    STEP(H,b,c,d,a,x[ 6],23,0x04881d05);
    STEP(H,a,b,c,d,x[ 9], 4,0xd9d4d039);
    STEP(H,d,a,b,c,x[12],11,0xe6db99e5);
    STEP(H,c,d,a,b,x[15],16,0x1fa27cf8);
    STEP(H,b,c,d,a,x[ 2],23,0xc4ac5665);

    /* Round 4 */
    STEP(I,a,b,c,d,x[ 0], 6,0xf4292244);
    STEP(I,d,a,b,c,x[ 7],10,0x432aff97);
    STEP(I,c,d,a,b,x[14],15,0xab9423a7);
    STEP(I,b,c,d,a,x[ 5],21,0xfc93a039);
    STEP(I,a,b,c,d,x[12], 6,0x655b59c3);
    STEP(I,d,a,b,c,x[ 3],10,0x8f0ccc92);
    STEP(I,c,d,a,b,x[10],15,0xffeff47d);
    STEP(I,b,c,d,a,x[ 1],21,0x85845dd1);
    STEP(I,a,b,c,d,x[ 8], 6,0x6fa87e4f);
    STEP(I,d,a,b,c,x[15],10,0xfe2ce6e0);
    STEP(I,c,d,a,b,x[ 6],15,0xa3014314);
    STEP(I,b,c,d,a,x[13],21,0x4e0811a1);
    STEP(I,a,b,c,d,x[ 4], 6,0xf7537e82);
    STEP(I,d,a,b,c,x[11],10,0xbd3af235);
    STEP(I,c,d,a,b,x[ 2],15,0x2ad7d2bb);
    STEP(I,b,c,d,a,x[ 9],21,0xeb86d391);

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

