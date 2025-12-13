#define _POSIX_C_SOURCE 200809L
#include "storage.h"
#include <assert.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "bencode.h"

/* Helper: read uint64 from bencoded info if needed is done by caller.
   storage_init_from_info expects info_buf to be the exact bencoded info dictionary.
   For simplicity, we parse only: "piece length", "length" (single-file), "name", "pieces".
   This vanilla parser assumes the info dict is reasonably formed. 
   TODO: make adjustments for complicated dictionaries.
*/
#define STORAGE_BLOCK_SIZE 16384

// static const unsigned char *find_key(const unsigned char *buf, size_t len, const char *key, size_t *val_start, size_t *val_len);

static void make_storage_path(storage_t *s, const char *torrent_name) {
    const char *base = NULL;
    if (torrent_name && torrent_name[0]) base = torrent_name;
    else if (s->name[0]) base = s->name;
    else base = "torrent_data";
    snprintf(s->storage_path, sizeof(s->storage_path), "%s.data", base);
}

static void set_have_bit(storage_t *s, uint32_t index) {
    size_t byte = index / 8;
    size_t bit = 7 - (index % 8);
    s->have_bits[byte] |= (1u << bit);
}
static int get_have_bit(storage_t *s, uint32_t index) {
    size_t byte = index / 8;
    size_t bit = 7 - (index % 8);
    return (s->have_bits[byte] >> bit) & 1;
}
static void set_block_bit(storage_t *s, uint32_t global_block_index) {
    size_t byte = global_block_index / 8;
    size_t bit = 7 - (global_block_index % 8);
    s->block_bits[byte] |= (1u << bit);
}
static int get_block_bit(storage_t *s, uint32_t global_block_index) {
    size_t byte = global_block_index / 8;
    size_t bit = 7 - (global_block_index % 8);
    return (s->block_bits[byte] >> bit) & 1;
}
static uint32_t blocks_in_piece(storage_t *s, uint32_t index) {
    return s->block_off[index + 1] - s->block_off[index];
}
static int piece_all_blocks_present(storage_t *s, uint32_t index) {
    uint32_t base = s->block_off[index];
    uint32_t n = blocks_in_piece(s, index);
    for (uint32_t i = 0; i < n; i++) {
        if (!get_block_bit(s, base + i)) return 0;
    }
    return 1;
}

static void clear_piece_blocks(storage_t *s, uint32_t index) {
    uint32_t base = s->block_off[index];
    uint32_t n = blocks_in_piece(s, index);

    for (uint32_t i = 0; i < n; i++) {
        uint32_t gi = base + i;
        size_t byte = gi / 8;
        size_t bit = 7 - (gi % 8);
        s->block_bits[byte] &= (unsigned char)~(1 << bit);
    }
}

static int verify_piece_sha256(storage_t *s, uint32_t index) {
    uint32_t psize = storage_piece_size(s, index);
    unsigned char *buf = malloc(psize ? psize : 1);
    if (!buf) return -1;
    if (storage_read_block(s, index, 0, buf, psize) != 0) {
        free(buf); return -1;
    }
    unsigned char digest[32];
    unsigned int dlen;
    EVP_MD_CTX *ctx_sha256 = EVP_MD_CTX_new();
    if (!ctx_sha256) {
        free(buf);
        return -1;
    }
    EVP_DigestInit_ex(ctx_sha256, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx_sha256, buf, psize);
    EVP_DigestFinal_ex(ctx_sha256, digest, &dlen);
    EVP_MD_CTX_free(ctx_sha256);
    int ok = 0;
    if (s->piece_hash_len == 32) {
        if (memcmp(digest, s->pieces_hashes + (size_t)index * 32, 32) == 0) ok = 1;
    } else if (s->piece_hash_len == 20) {
        // compute SHA1 and compare
        unsigned char sha1d[20];
        EVP_MD_CTX *ctx_sha1 = EVP_MD_CTX_new();
        if (ctx_sha1) {
            EVP_DigestInit_ex(ctx_sha1, EVP_sha1(), NULL);
            EVP_DigestUpdate(ctx_sha1, buf, psize);
            EVP_DigestFinal_ex(ctx_sha1, sha1d, &dlen);
            EVP_MD_CTX_free(ctx_sha1);
            if (memcmp(sha1d, s->pieces_hashes + (size_t)index * 20, 20) == 0) ok = 1;
        }
        // also accept if truncated SHA-256 matches first 20 bytes
        if (!ok && memcmp(digest, s->pieces_hashes + (size_t)index * 20, 20) == 0) ok = 1;
    } else {
        ok = 0;
    }
    free(buf);
    return ok ? 0 : -2;
}

/* ---------- streaming bencode extraction for info dict ---------- */

typedef enum {
    WANT_NONE = 0,
    WANT_PIECE_LEN,
    WANT_PIECES,
    WANT_NAME,
    WANT_LENGTH_ROOT,
    WANT_LENGTH_FILE
} want_t;

typedef struct {
    storage_t *s;
    want_t want;

    int dict_depth;
    int list_depth;

    char last_key[64];

    int in_files_list;
    int files_list_depth;

    int in_file_dict;
    int file_dict_depth;

    uint64_t files_total;

    int got_piece_len;
    int got_pieces;
    int got_name;
    int got_length_root;
    int got_files;
} parse_ctx_t;

static int keyeq(const char *k, size_t klen, const char *lit) {
    size_t L = strlen(lit);
    return (klen == L && memcmp(k, lit, L) == 0);
}

static void cb_dict_enter(void *u) {
    parse_ctx_t *c = u;
    c->dict_depth++;

    if (c->in_files_list && !c->in_file_dict) {
        /* file dicts are inside root's "files" list; keep it simple */
        c->in_file_dict = 1;
        c->file_dict_depth = c->dict_depth;
    }
}

static void cb_dict_leave(void *u) {
    parse_ctx_t *c = u;

    if (c->in_file_dict && c->dict_depth == c->file_dict_depth) {
        c->in_file_dict = 0;
        c->file_dict_depth = 0;
    }

    c->dict_depth--;
    if (c->dict_depth < 0) c->dict_depth = 0;
}

static void cb_list_enter(void *u) {
    parse_ctx_t *c = u;
    c->list_depth++;

    if (c->dict_depth == 1 && strcmp(c->last_key, "files") == 0) {
        c->in_files_list = 1;
        c->files_list_depth = c->list_depth;
        c->got_files = 1;
    }
}

static void cb_list_leave(void *u) {
    parse_ctx_t *c = u;

    if (c->in_files_list && c->list_depth == c->files_list_depth) {
        c->in_files_list = 0;
        c->files_list_depth = 0;
    }

    c->list_depth--;
    if (c->list_depth < 0) c->list_depth = 0;
}

static void cb_dict_key(const char *s, size_t len, void *u) {
    parse_ctx_t *c = u;

    size_t n = len < sizeof(c->last_key) - 1 ? len : (sizeof(c->last_key) - 1);
    memcpy(c->last_key, s, n);
    c->last_key[n] = 0;

    c->want = WANT_NONE;

    if (c->dict_depth == 1) {
        if (keyeq(s, len, "piece length")) c->want = WANT_PIECE_LEN;
        else if (keyeq(s, len, "pieces")) c->want = WANT_PIECES;
        else if (keyeq(s, len, "name")) c->want = WANT_NAME;
        else if (keyeq(s, len, "length")) c->want = WANT_LENGTH_ROOT;
        else c->want = WANT_NONE;
        return;
    }

    if (c->in_file_dict && keyeq(s, len, "length")) {
        c->want = WANT_LENGTH_FILE;
        return;
    }
}

static void cb_hit_int(long long v, void *u) {
    parse_ctx_t *c = u;

    if (c->want == WANT_PIECE_LEN) {
        if (v <= 0 || v > 0x7fffffff) return;
        c->s->piece_len = (uint32_t)v;
        c->got_piece_len = 1;
    } else if (c->want == WANT_LENGTH_ROOT) {
        if (v < 0) return;
        c->s->total_length = (uint64_t)v;
        c->got_length_root = 1;
    } else if (c->want == WANT_LENGTH_FILE) {
        if (v < 0) return;
        c->files_total += (uint64_t)v;
    }

    c->want = WANT_NONE;
}

static void cb_hit_str(const char *s, size_t len, void *u) {
    parse_ctx_t *c = u;

    if (c->want == WANT_NAME) {
        size_t n = len < (sizeof(c->s->name) - 1) ? len : (sizeof(c->s->name) - 1);
        memcpy(c->s->name, s, n);
        c->s->name[n] = 0;
        c->got_name = 1;
    } else if (c->want == WANT_PIECES) {
        if (len == 0) return;

        if (len % 32 == 0) c->s->piece_hash_len = 32;
        else if (len % 20 == 0) c->s->piece_hash_len = 20;
        else return;

        c->s->num_pieces = (uint32_t)(len / c->s->piece_hash_len);
        c->s->pieces_hashes = malloc(len);
        if (!c->s->pieces_hashes) return;
        memcpy(c->s->pieces_hashes, s, len);
        c->got_pieces = 1;
    }

    c->want = WANT_NONE;
}
/* initialize: parse piece length, pieces (raw), length, name */
int storage_init_from_info(storage_t *storage, const unsigned char *info_buf, size_t info_len, const char *torrent_name) {
   // fprintf(stderr, "[DEBUG] storage_init_from_info: Entry\n");
    if (!storage || !info_buf || info_len == 0) {
     //    fprintf(stderr, "[DEBUG] storage_init_from_info: storage or info_buf is NULL\n");
        return -1;
    }
    memset(storage, 0, sizeof(*storage));
    parse_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.s = storage;
    bencode_callbacks_t cbs;
    memset(&cbs, 0, sizeof(cbs));
    cbs.dict_enter = cb_dict_enter;
    cbs.dict_leave = cb_dict_leave;
    cbs.list_enter = cb_list_enter;
    cbs.list_leave = cb_list_leave;
    cbs.dict_key = cb_dict_key;
    cbs.hit_int = cb_hit_int;
    cbs.hit_str = cb_hit_str;

    bencode_t *b = bencode_new(64, &cbs, &ctx);
    if (!b) return -1;
    
    if (!bencode_dispatch_from_buffer(b, info_buf, info_len)) {
        bencode_free(b);
        return -1;
    }
    bencode_free(b);
    if (!ctx.got_piece_len){
        fprintf(stderr, "[storage] missing piece length\n");
        return -1;
    }
    if (!ctx.got_pieces){
        fprintf(stderr, "[storage] missing pieces\n");
        return -1;
    }
    if (!ctx.got_length_root){
        if (ctx.got_files) {
            storage->total_length = ctx.files_total;

        }else {
            fprintf(stderr, "[storage] missing length (and no files list)\n");
            return -1;
        }
    }

    if (storage->total_length == 0) {
        fprintf(stderr, "[storage] total length is zero\n");
        return -1;
    }

    make_storage_path(storage, torrent_name);

    // ensure file exists and is total_length bytes (create if missing)
    // fprintf(stderr, "[DEBUG] storage_init_from_info: Before open storage_path %s\n", storage->storage_path);
    int fd = open(storage->storage_path, O_RDWR | O_CREAT, 0666);
    if (fd < 0) { perror("open storage"); return -1; }
    // fprintf(stderr, "[DEBUG] storage_init_from_info: After open storage_path\n");
    struct stat st;
    if (fstat(fd, &st) == 0) {
        if ((uint64_t)st.st_size < storage->total_length) {
            // fprintf(stderr, "[DEBUG] storage_init_from_info: Truncating file\n");
            if (ftruncate(fd, (off_t)storage->total_length) != 0) {
                perror("ftruncate");
                close(fd);
                return -1;
            }
        }
    }
    close(fd);

    // piece bitfiled
    size_t bits_bytes = (storage->num_pieces + 7) / 8;
    storage->have_bits = calloc(1, bits_bytes);
    if (!storage->have_bits) return -1;

    // block tracking
    storage->block_size = STORAGE_BLOCK_SIZE;
    storage->block_off = calloc((size_t)storage->num_pieces + 1, sizeof(uint32_t));
    if (!storage->block_off) return -1;

    uint32_t total_blocks = 0;
    storage->block_off[0] = 0;
    for (uint32_t i = 0; i < storage->num_pieces; i++) {
        uint32_t psize = storage_piece_size(storage, i);
        uint32_t nblk = (psize + storage->block_size - 1) / storage->block_size;
        total_blocks += nblk;
        storage->block_off[i + 1] = total_blocks;
    }
    storage->block_bits_bytes = (total_blocks + 7) / 8;
    storage->block_bits = calloc(1, storage->block_bits_bytes ? storage->block_bits_bytes : 1);
    if (!storage->block_bits) return -1;

    fprintf(stderr,
            "[storage] init: pieces=%u piece_len=%u piece_hash_len=%zu total=%llu path=%s\n",
            storage->num_pieces, storage->piece_len, storage->piece_hash_len,
            (unsigned long long)storage->total_length, storage->storage_path);
    //fprintf(stderr, "[DEBUG] storage_init_from_info: Exit success\n");
    return 0;
}
void storage_free(storage_t *s) {
    if (!s) return;
    free(s->pieces_hashes); s->pieces_hashes = NULL;
    free(s->have_bits); s->have_bits = NULL;
    free(s->block_bits); s->block_bits = NULL;
    free(s->block_off); s->block_off = NULL;
    s->block_bits_bytes = 0;
}

int storage_get_bitfield(storage_t *s, unsigned char *out_bits, size_t out_len) {
    size_t bytes = (s->num_pieces + 7) / 8;
    if (out_len < bytes) return -1;
    memcpy(out_bits, s->have_bits, bytes);
    return 0;
}

uint32_t storage_num_pieces(storage_t *s) {return s->num_pieces;}
uint32_t storage_piece_length(storage_t *s) {return s->piece_len;}

uint32_t storage_piece_size(storage_t *s, uint32_t index) {
    if (index + 1 == s->num_pieces) {
        uint64_t rem = s->total_length - ((uint64_t)index * s->piece_len);
        return (uint32_t)rem;
    }
    return s->piece_len;
}

int storage_read_block(storage_t *s, uint32_t index, uint32_t begin, void *buf, uint32_t length) {
    if (index >= s->num_pieces) return -1;
    uint32_t psize = storage_piece_size(s, index);
    if (begin + length > psize) return -1;
    off_t offset = (off_t)index * (off_t)s->piece_len + (off_t)begin;
    int fd = open(s->storage_path, O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) { close (fd); return -1; }
    ssize_t r = read(fd, buf, length);
    close(fd);
    return (r==(ssize_t)length) ? 0 : -1;
}

int storage_write_block_and_check(storage_t *s, uint32_t index, uint32_t begin, const void *buf, uint32_t length) {
    if (index >= s->num_pieces) return -1;
    uint32_t psize = storage_piece_size(s, index);
    if (begin + length > psize) return -1;
    off_t offset = (off_t)index * (off_t)s->piece_len + (off_t)begin;
    int fd = open(s->storage_path, O_RDWR);
    if (fd < 0) return -1;
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) { close(fd); return -1; }
    ssize_t w = write(fd, buf, length);
    close(fd);
    if (w != (ssize_t)length) { return -1; }

    // mark block as present (assume request align to block boundaries)
    uint32_t first = begin / s->block_size;
    uint32_t last = (begin + length - 1) / s->block_size;
    uint32_t base = s->block_off[index];
    uint32_t nblk = blocks_in_piece(s, index);

    for (uint32_t b = first; b <= last; b++){
        if (b < nblk) set_block_bit(s, base + b);
    }
    if (storage_is_piece_complete(s, index)) return 0;
    if (!piece_all_blocks_present(s, index)) {
        return 0;
    }
    // Check if all bytes of piece are non-zero? Simpler: always verify when write occurs for now.

    // TODO: track which blocks are present. For simplicity, verify entire piece now. 

    int ver = verify_piece_sha256(s, index);
    if (ver == 0) {
        set_have_bit(s, index);
        return 0;
    } 
    clear_piece_blocks(s, index);
    return -2;
}

int storage_is_piece_complete(storage_t *s, uint32_t index) {
    if (index >= s->num_pieces) return 0;
    return get_have_bit(s, index);
}