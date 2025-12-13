#ifndef BENCODE_H
#define BENCODE_H

#include <stddef.h>

enum {
    BENCODE_NONE,
    BENCODE_INT,
    BENCODE_STRLEN,
    BENCODE_STRING,
    BENCODE_LIST,
    BENCODE_DICT
};

typedef struct bencode_frame_t {
    int type;
    long long intval;
    int negative;       /* added for negative ints */
    char *strval;
    size_t strlen, strcap;
    int dict_expect_key; // 1 if next element is key, 0 if value
} bencode_frame_t;

typedef struct bencode_callbacks_t {
    void (*hit_int)(long long v, void *u);
    void (*hit_str)(const char *s, size_t len, void *u);
    void (*dict_enter)(void *u);
    void (*dict_leave)(void *u);
    void (*list_enter)(void *u);
    void (*list_leave)(void *u);
    void (*dict_key)(const char *s, size_t len, void *u);
} bencode_callbacks_t;

typedef struct bencode_t {
    bencode_callbacks_t *cbs;
    void *u;
    bencode_frame_t **stk;
    size_t stklen, stkcap;
} bencode_t;

bencode_t *bencode_new(size_t nframes, bencode_callbacks_t *cbs, void *u);
void bencode_free(bencode_t *me);
int bencode_dispatch_from_buffer(bencode_t *me, const void *buf, size_t len); // 1 on success, 0 on parse error

#endif
