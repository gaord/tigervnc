#ifndef CRYPTO_MOCK_H
#define CRYPTO_MOCK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct md5_ctx {
    uint32_t state[4];
    uint32_t count[2];
    uint8_t buffer[64];
};

void md5_init(struct md5_ctx *context);
void md5_update(struct md5_ctx *context, size_t length, const uint8_t *data);
void md5_digest(struct md5_ctx *context, size_t length, uint8_t *digest);

struct aes128_ctx {
    uint32_t round_key[44];
};

void aes128_set_encrypt_key(struct aes128_ctx *ctx, const uint8_t *key);
void aes128_encrypt(struct aes128_ctx *ctx, size_t length, uint8_t *dst, const uint8_t *src);

#ifdef __cplusplus
}
#endif

#endif
