#ifndef BENCODE_WRITE_H
#define BENCODE_WRITE_H

#include <stddef.h>
#include <stdint.h>

/* Opaque writer */
typedef struct benc_w benc_w;

/* create writer with initial capacity */
benc_w *bencw_new(size_t cap);

/* free writer and buffer */
void bencw_free(benc_w *w);

/* append raw bytes */
int bencw_append(benc_w *w, const void *data, size_t len);

/* convenience writes */
int bencw_put_str(benc_w *w, const char *s, size_t len); /* writes "<len>:<s>" */
int bencw_put_int(benc_w *w, long long v);              /* writes "i<digits>e" */

int bencw_start_dict(benc_w *w); /* writes 'd' */
int bencw_end_dict(benc_w *w);   /* writes 'e' */

int bencw_start_list(benc_w *w); /* writes 'l' */
int bencw_end_list(benc_w *w);   /* writes 'e' */

/* get buffer pointer & length (caller must not free; free via bencw_free) */
const unsigned char *bencw_buf(benc_w *w);
size_t bencw_len(benc_w *w);

/* reserve/ensure capacity */
int bencw_ensure(benc_w *w, size_t extra);

#endif
