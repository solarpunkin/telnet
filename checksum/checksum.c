#include "checksum.h"

static uint32_t crc32_table[256];
static int crc32_table_init = 0;

static void crc32_make_table(void) {
    for (uint32_t i = 0; i < 256; i++)
    {
        uint32_t c = i;
        for (int k = 0; k < 8; k ++) {
            c = (c & 1) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        }
        crc32_table[i] = c;
    }
    crc32_table_init = 1;
}

void crc32_init (crc32_ctx *ctx) {
    if (!crc32_table_init) crc32_make_table();
    ctx -> state = 0xFFFFFFFFu;
}

void crc32_update(crc32_ctx *ctx, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char*)data;
    uint32_t c = ctx->state;
    for (size_t i = 0; i < len; i++)
    {
        c = crc32_table[(c^p[i]) & 0xFFu] ^ (c >> 8);
    }
    ctx->state = c;

}

uint32_t crc32_final(crc32_ctx *ctx) {
    return ctx->state ^ 0xFFFFFFFFu;
}