#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bencode_write.h"

struct benc_w {
    unsigned char *buf;
    size_t len;
    size_t cap;
};

static int grow(benc_w *w, size_t need) {
    if (!w) return -1;
    if (w->len + need <= w->cap) return 0;
    size_t ncap = w->cap ? w->cap * 2 : 1024;
    while (ncap < w->len + need) ncap *= 2;
    unsigned char *nb = realloc(w->buf, ncap);
    if (!nb) return -1;
    w->buf = nb;
    w->cap = ncap;
    return 0;
}

benc_w *bencw_new(size_t cap) {
    benc_w *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    if (cap == 0) cap = 1024;
    w->buf = malloc(cap);
    if (!w->buf) { free(w); return NULL; }
    w->cap = cap;
    w->len = 0;
    return w;
}

void bencw_free(benc_w *w) {
    if (!w) return;
    if (w->buf) free(w->buf);
    free(w);
}

const unsigned char *bencw_buf(benc_w *w) { return w ? w->buf : NULL; }
size_t bencw_len(benc_w *w) { return w ? w->len : 0; }

int bencw_ensure(benc_w *w, size_t extra) { return grow(w, extra); }

int bencw_append(benc_w *w, const void *data, size_t len) {
    if (!w) return -1;
    if (grow(w, len) != 0) return -1;
    memcpy(w->buf + w->len, data, len);
    w->len += len;
    return 0;
}

int bencw_put_str(benc_w *w, const char *s, size_t len) {
    if (!w) return -1;
    char tmp[64];
    int n = snprintf(tmp, sizeof(tmp), "%zu:", len);
    if (n < 0) return -1;
    if (bencw_append(w, tmp, (size_t)n) != 0) return -1;
    if (len > 0) {
        if (bencw_append(w, s, len) != 0) return -1;
    }
    return 0;
}

int bencw_put_int(benc_w *w, long long v) {
    if (!w) return -1;
    char tmp[64];
    int n = snprintf(tmp, sizeof(tmp), "i%llde", v);
    if (n < 0) return -1;
    return bencw_append(w, tmp, (size_t)n);
}

int bencw_start_dict(benc_w *w) {
    char c = 'd';
    return bencw_append(w, &c, 1);
}
int bencw_end_dict(benc_w *w) {
    char c = 'e';
    return bencw_append(w, &c, 1);
}
int bencw_start_list(benc_w *w) {
    char c = 'l';
    return bencw_append(w, &c, 1);
}
int bencw_end_list(benc_w *w) {
    char c = 'e';
    return bencw_append(w, &c, 1);
}
