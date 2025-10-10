#include <stdio.h>
#include <string.h>
#include "bencode.h"  // copy this file to bencoder

static void hit_str(const char *s, size_t len, void *u) {
    printf("str: %.*s\n", (int)len, s);
}
static void hit_int(long long v, void *u) {
    printf("int: %lld\n", v);
}
static void dict_enter(void *u) { printf("{\n"); }
static void dict_leave(void *u) { printf("}\n"); }

int main() {
    const char *torrent = "d8:intervali1800e5:peersld2:ip9:127.0.0.14:porti6881e7:peer id20:-PC0001-123456789012eee";
    bencode_callbacks_t cb = { .hit_str=hit_str, .hit_int=hit_int,
                               .dict_enter=dict_enter, .dict_leave=dict_leave };
    bencode_t *b = bencode_new(16, &cb, NULL);
    bencode_dispatch_from_buffer(b, torrent, strlen(torrent));
    bencode_free(b);
    return 0;
}
