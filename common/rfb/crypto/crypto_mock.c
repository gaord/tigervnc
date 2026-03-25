#include "crypto_mock.h"
#include <string.h>

// --- MD5 Implementation ---
#define F(x, y, z)   ((z) ^ ((x) & ((y) ^ (z))))
#define G(x, y, z)   ((y) ^ ((z) & ((x) ^ (y))))
#define H(x, y, z)   ((x) ^ (y) ^ (z))
#define I(x, y, z)   ((y) ^ ((x) | ~(z)))

#define STEP(f, a, b, c, d, x, t, s) \
    (a) += f((b), (c), (d)) + (x) + (t); \
    (a) = (((a) << (s)) | (((a) & 0xffffffff) >> (32 - (s)))); \
    (a) += (b);

static void md5_transform(uint32_t state[4], const uint8_t block[64]) {
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t x[16];
    for (int i = 0, j = 0; i < 16; i++, j += 4)
        x[i] = ((uint32_t)block[j]) | (((uint32_t)block[j + 1]) << 8) |
               (((uint32_t)block[j + 2]) << 16) | (((uint32_t)block[j + 3]) << 24);

    STEP(F, a, b, c, d, x[ 0], 0xd76aa478,  7)
    STEP(F, d, a, b, c, x[ 1], 0xe8c7b756, 12)
    STEP(F, c, d, a, b, x[ 2], 0x242070db, 17)
    STEP(F, b, c, d, a, x[ 3], 0xc1bdceee, 22)
    STEP(F, a, b, c, d, x[ 4], 0xf57c0faf,  7)
    STEP(F, d, a, b, c, x[ 5], 0x4787c62a, 12)
    STEP(F, c, d, a, b, x[ 6], 0xa8304613, 17)
    STEP(F, b, c, d, a, x[ 7], 0xfd469501, 22)
    STEP(F, a, b, c, d, x[ 8], 0x698098d8,  7)
    STEP(F, d, a, b, c, x[ 9], 0x8b44f7af, 12)
    STEP(F, c, d, a, b, x[10], 0xffff5bb1, 17)
    STEP(F, b, c, d, a, x[11], 0x895cd7be, 22)
    STEP(F, a, b, c, d, x[12], 0x6b901122,  7)
    STEP(F, d, a, b, c, x[13], 0xfd987193, 12)
    STEP(F, c, d, a, b, x[14], 0xa679438e, 17)
    STEP(F, b, c, d, a, x[15], 0x49b40821, 22)

    STEP(G, a, b, c, d, x[ 1], 0xf61e2562,  5)
    STEP(G, d, a, b, c, x[ 6], 0xc040b340,  9)
    STEP(G, c, d, a, b, x[11], 0x265e5a51, 14)
    STEP(G, b, c, d, a, x[ 0], 0xe9b6c7aa, 20)
    STEP(G, a, b, c, d, x[ 5], 0xd62f105d,  5)
    STEP(G, d, a, b, c, x[10], 0x02441453,  9)
    STEP(G, c, d, a, b, x[15], 0xd8a1e681, 14)
    STEP(G, b, c, d, a, x[ 4], 0xe7d3fbc8, 20)
    STEP(G, a, b, c, d, x[ 9], 0x21e1cde6,  5)
    STEP(G, d, a, b, c, x[14], 0xc33707d6,  9)
    STEP(G, c, d, a, b, x[ 3], 0xf4d50d87, 14)
    STEP(G, b, c, d, a, x[ 8], 0x455a14ed, 20)
    STEP(G, a, b, c, d, x[13], 0xa9e3e905,  5)
    STEP(G, d, a, b, c, x[ 2], 0xfcefa3f8,  9)
    STEP(G, c, d, a, b, x[ 7], 0x676f02d9, 14)
    STEP(G, b, c, d, a, x[12], 0x8d2a4c8a, 20)

    STEP(H, a, b, c, d, x[ 5], 0xfffa3942,  4)
    STEP(H, d, a, b, c, x[ 8], 0x8771f681, 11)
    STEP(H, c, d, a, b, x[11], 0x6d9d6122, 16)
    STEP(H, b, c, d, a, x[14], 0xfde5380c, 23)
    STEP(H, a, b, c, d, x[ 1], 0xa4beea44,  4)
    STEP(H, d, a, b, c, x[ 4], 0x4bdecfa9, 11)
    STEP(H, c, d, a, b, x[ 7], 0xf6bb4b60, 16)
    STEP(H, b, c, d, a, x[10], 0xbebfbc70, 23)
    STEP(H, a, b, c, d, x[13], 0x289b7ec6,  4)
    STEP(H, d, a, b, c, x[ 0], 0xeaa127fa, 11)
    STEP(H, c, d, a, b, x[ 3], 0xd4ef3085, 16)
    STEP(H, b, c, d, a, x[ 6], 0x04881d05, 23)
    STEP(H, a, b, c, d, x[ 9], 0xd9d4d039,  4)
    STEP(H, d, a, b, c, x[12], 0xe6db99e5, 11)
    STEP(H, c, d, a, b, x[15], 0x1fa27cf8, 16)
    STEP(H, b, c, d, a, x[ 2], 0xc4ac5665, 23)

    STEP(I, a, b, c, d, x[ 0], 0xf4292244,  6)
    STEP(I, d, a, b, c, x[ 7], 0x432aff97, 10)
    STEP(I, c, d, a, b, x[14], 0xab9423a7, 15)
    STEP(I, b, c, d, a, x[ 5], 0xfc93a039, 21)
    STEP(I, a, b, c, d, x[12], 0x655b59c3,  6)
    STEP(I, d, a, b, c, x[ 3], 0x8f0ccc92, 10)
    STEP(I, c, d, a, b, x[10], 0xffeff47d, 15)
    STEP(I, b, c, d, a, x[ 1], 0x85845dd1, 21)
    STEP(I, a, b, c, d, x[ 8], 0x6fa87e4f,  6)
    STEP(I, d, a, b, c, x[15], 0xfe2ce6e0, 10)
    STEP(I, c, d, a, b, x[ 6], 0xa3014314, 15)
    STEP(I, b, c, d, a, x[13], 0x4e0811a1, 21)
    STEP(I, a, b, c, d, x[ 4], 0xf7537e82,  6)
    STEP(I, d, a, b, c, x[11], 0xbd3af235, 10)
    STEP(I, c, d, a, b, x[ 2], 0x2ad7d2bb, 15)
    STEP(I, b, c, d, a, x[ 9], 0xeb86d391, 21)

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
}

void md5_init(struct md5_ctx *context) {
    context->count[0] = context->count[1] = 0;
    context->state[0] = 0x67452301;
    context->state[1] = 0xefcdab89;
    context->state[2] = 0x98badcfe;
    context->state[3] = 0x10325476;
}

void md5_update(struct md5_ctx *context, size_t length, const uint8_t *data) {
    size_t i, index, partLen;
    index = (size_t)((context->count[0] >> 3) & 0x3F);
    if ((context->count[0] += ((uint32_t)length << 3)) < ((uint32_t)length << 3))
        context->count[1]++;
    context->count[1] += ((uint32_t)length >> 29);
    partLen = 64 - index;
    if (length >= partLen) {
        memcpy(&context->buffer[index], data, partLen);
        md5_transform(context->state, context->buffer);
        for (i = partLen; i + 63 < length; i += 64)
            md5_transform(context->state, &data[i]);
        index = 0;
    } else {
        i = 0;
    }
    memcpy(&context->buffer[index], &data[i], length - i);
}

void md5_digest(struct md5_ctx *context, size_t length, uint8_t *digest) {
    uint8_t bits[8];
    size_t index, padLen;
    uint32_t c0 = context->count[0], c1 = context->count[1];
    bits[0] = c0 & 0xff; bits[1] = (c0 >> 8) & 0xff; bits[2] = (c0 >> 16) & 0xff; bits[3] = (c0 >> 24) & 0xff;
    bits[4] = c1 & 0xff; bits[5] = (c1 >> 8) & 0xff; bits[6] = (c1 >> 16) & 0xff; bits[7] = (c1 >> 24) & 0xff;
    index = (size_t)((context->count[0] >> 3) & 0x3f);
    padLen = (index < 56) ? (56 - index) : (120 - index);
    static const uint8_t padding[64] = {0x80};
    md5_update(context, padLen, padding);
    md5_update(context, 8, bits);
    for (int i = 0; i < 4 && i * 4 < length; i++) {
        digest[i * 4] = context->state[i] & 0xff;
        if (i * 4 + 1 < length) digest[i * 4 + 1] = (context->state[i] >> 8) & 0xff;
        if (i * 4 + 2 < length) digest[i * 4 + 2] = (context->state[i] >> 16) & 0xff;
        if (i * 4 + 3 < length) digest[i * 4 + 3] = (context->state[i] >> 24) & 0xff;
    }
}

// --- AES-128 ECB Implementation ---
static const uint8_t sbox[256] = {
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rcon[10] = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

void aes128_set_encrypt_key(struct aes128_ctx *ctx, const uint8_t *key) {
    for (int i = 0; i < 4; i++)
        ctx->round_key[i] = (key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3];
    for (int i = 4; i < 44; i++) {
        uint32_t temp = ctx->round_key[i - 1];
        if (i % 4 == 0) {
            temp = (temp << 8) | (temp >> 24);
            temp = (sbox[(temp >> 24) & 0xff] << 24) | (sbox[(temp >> 16) & 0xff] << 16) |
                   (sbox[(temp >> 8) & 0xff] << 8) | sbox[temp & 0xff];
            temp ^= (rcon[i / 4 - 1] << 24);
        }
        ctx->round_key[i] = ctx->round_key[i - 4] ^ temp;
    }
}

static uint8_t mul2(uint8_t a) { return (a & 0x80) ? ((a << 1) ^ 0x1b) : (a << 1); }

void aes128_encrypt(struct aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src) {
    for (size_t offset = 0; offset < length; offset += 16) {
        uint8_t state[16];
        for (int i = 0; i < 16; i++) {
            state[i] = src[offset + i] ^ ((ctx->round_key[i / 4] >> (24 - (i % 4) * 8)) & 0xff);
        }
        for (int round = 1; round <= 10; round++) {
            for (int i = 0; i < 16; i++) state[i] = sbox[state[i]];
            uint8_t temp[16];
            temp[0] = state[0]; temp[1] = state[5]; temp[2] = state[10]; temp[3] = state[15];
            temp[4] = state[4]; temp[5] = state[9]; temp[6] = state[14]; temp[7] = state[3];
            temp[8] = state[8]; temp[9] = state[13]; temp[10] = state[2]; temp[11] = state[7];
            temp[12] = state[12]; temp[13] = state[1]; temp[14] = state[6]; temp[15] = state[11];
            if (round < 10) {
                for (int i = 0; i < 4; i++) {
                    uint8_t a = temp[i*4], b = temp[i*4+1], c = temp[i*4+2], d = temp[i*4+3];
                    state[i*4]   = mul2(a) ^ mul2(b) ^ b ^ c ^ d;
                    state[i*4+1] = a ^ mul2(b) ^ mul2(c) ^ c ^ d;
                    state[i*4+2] = a ^ b ^ mul2(c) ^ mul2(d) ^ d;
                    state[i*4+3] = mul2(a) ^ a ^ b ^ c ^ mul2(d);
                }
            } else {
                for (int i = 0; i < 16; i++) state[i] = temp[i];
            }
            for (int i = 0; i < 16; i++) {
                state[i] ^= ((ctx->round_key[round * 4 + i / 4] >> (24 - (i % 4) * 8)) & 0xff);
            }
        }
        for (int i = 0; i < 16; i++) dst[offset + i] = state[i];
    }
}
