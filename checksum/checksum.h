#ifndef CHECKSUM_H
#define CHECKSUM_H

#include <stdint.h>
#include <stddef.h>

/* CRC32 (IEEE 802.3, polynomial 0xEDB88320, initial 0xFFFFFFFF, final xor 0xFFFFFFFF) */
typedef struct {
    uint32_t state;
} crc32_ctx;

void crc32_init(crc32_ctx *ctx);
void crc32_update(crc32_ctx *ctx, const void *data, size_t len);
uint32_t crc32_final(crc32_ctx *ctx);

/* SHA1 via OpenSSL libcrypto */
#include <openssl/sha.h>
typedef SHA_CTX sha1_ctx;

static inline void sha1_init(sha1_ctx *ctx) { SHA1_Init(ctx); }
static inline void sha1_update(sha1_ctx *ctx, const void *data, size_t len) { SHA1_Update(ctx, data, len); }
static inline void sha1_final(sha1_ctx *ctx, unsigned char out[20]) { SHA1_Final(out, ctx); }

#endif
