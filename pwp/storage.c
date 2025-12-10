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

/* Helper: read uint64 from bencoded info if needed is done by caller.
   storage_init_from_info expects info_buf to be the exact bencoded info dictionary.
   For simplicity, we parse only: "piece length", "length" (single-file), "name", "pieces".
   This vanilla parser assumes the info dict is reasonably formed. 
   TODO: make adjustments for complicated dictionaries.
*/

static const unsigned char *find_key(const unsigned char *buf, size_t len, const char *key, size_t *val_start, size_t *val_len);

static void make_storage_path(storage_t *s, const char *torrent_name) {
    if (torrent_name && torrent_name[0])
    snprintf(s->storage_path, sizeof(s->storage_path), "%s.data", torrent_name);
    else
    snprintf(s->storage_path, sizeof(s->storage_path), "torrent_data.data");
}

static const unsigned char *scan_bencode_value(const unsigned char *p, const unsigned char *end, size_t *out_len)
{
    if (p >= end) return NULL;
    unsigned char c = *p;
    if (c == 'i') {
        const unsigned char *q = p+1;
        while (q < end && *q != 'e') q++;
        if (q >= end) return NULL;
        *out_len = (size_t)(q - p + 1);
        return p;
    } else if (c == 'l' || c == 'd') {
        // naive: find matching 'e'
        int depth = 1;
        const unsigned char *q = p+1;
        while (q < end && depth > 0) {
            if (*q == 'l' || *q == 'd') depth++;
            else if (*q == 'e') depth--;
            else if (*q >= '0' && *q <= '9') {
                // skip string
                const unsigned char *r = q;
                while (r < end && *r != ':') r++;
                if (r >= end) return NULL;
                char tmp[32]; size_t m = r - q;
                if (m >= sizeof(tmp)) return NULL;
                memcpy(tmp, q, m); tmp[m]=0;
                long sl = atol(tmp);
                r++;
                q = r + sl;
                continue;
            }
            q++;
        }
        if (depth != 0) return NULL;
        *out_len = (size_t)(q - p);
        return p;
    } else if (c >= '0' && c <= '9') {
        const unsigned char *r = p;
        while (r < end && *r != ':') r++;
        if (r >= end) return NULL;
        char tmp[32]; size_t m = r - p;
        if (m >= sizeof(tmp)) return NULL;
        memcpy(tmp, p, m); tmp[m] = 0;
        long sl = atol(tmp);
        const unsigned char *start = r + 1;
        if (start + sl > end) return NULL;
        *out_len = (size_t)(sl);
        return start;
    }
    return NULL;
}

static const unsigned char *find_key(const unsigned char *buf, size_t len, const char *key, size_t *val_start, size_t *val_len) {
    const unsigned char *end = buf + len;
    // brute force scan for key string
    size_t keylen = strlen(key);
    if(len > 0 && p[0] == 'd') {
        p++;
    } else return NULL;
    while (p < end && *p !='e')
    {
        if(!(*p >= '0' && *p <= '9')) return NULL;
        const unsigned char *col = p;
        while (col < end && *col != ':') col++;
        if (col >= end) break;
        char tmp[32]; size_t m = col - p;
            if (m >= sizeof(tmp)) {
                p = col; return NULL;
            }
            memcpy(tmp, p, m); tmp[m] = 0;
            long sl = atol(tmp);
            const unsigned char *s = col + 1;
            if (s + sl > end) { p = col; return NULL; }
            if (sl == (long)keylen && memcmp(s, key, keylen) == 0) {
                const unsigned char *after_key = s + sl;
                size_t vlen = 0;
                const unsigned char *valptr = scan_bencode_value(after_key, end, &vlen);
                if (!valptr) return NULL;
                *val_start = (size_t)(valptr - buf);
                *val_len = vlen;
                return valptr;
            }
            p = s + sl; // advance to last key
            size_t skipped_vlen = 0;
            const unsigned char *next_element_ptr = scan_bencode_value(p, end, &skipped_vlen);
            if (!next_element_ptr) return NULL; // malformed value after non-matching key
            p = next_element_ptr + skipped_vlen; 
    }
    return NULL; 
}

/* initialize: parse piece length, pieces (raw), length, name */
int storage_init_from_info(storage_t *storage, const unsigned char *info_buf, size_t info_len, const char *torrent_name) {
   // fprintf(stderr, "[DEBUG] storage_init_from_info: Entry\n");
    if (!storage || !info_buf) {
     //    fprintf(stderr, "[DEBUG] storage_init_from_info: storage or info_buf is NULL\n");
        return -1;
    }
    memset(storage, 0, sizeof(*storage));
    if (torrent_name) strncpy(storage->name, torrent_name, sizeof(storage->name)-1);

    // find piece length
    size_t start, vlen;
     // fprintf(stderr, "[DEBUG] storage_init_from_info: Before find_key for piece length\n");
    const unsigned char *p = find_key (info_buf, info_len, "piece length", &start, &vlen);
    if (!p) { fprintf(stderr, "[storage] missing piece length\n"); return -1; }
    // fprintf(stderr, "[DEBUG] storage_init_from_info: After find_key for piece length\n");
    if (p[0] != 'i') { fprintf(stderr, "[storage] piece length not integer\n"); return -1; }
    char tmp[32]; size_t i = 1; size_t j = 0;
    while (i < vlen && p[i] != 'e' && j+1 < sizeof(tmp)) tmp[j++] = p[i++]; tmp[j]=0;
    storage->piece_len = (uint32_t)atoi(tmp);
    // fprintf(stderr, "[DEBUG] storage_init_from_info: Before find_key for piece length\n");
    // find pieces string
    p = find_key(info_buf, info_len, "pieces", &start, &vlen);
    if (!p) { fprintf(stderr, "[storage] missing pieces\n"); return -1; }
    // fprintf(stderr, "[DEBUG] storage_init_from_info: After find_key for pieces\n");
    
    /* pieces value should be a string of 32*num pieces (for SHA-256) or 20*numpieces (legacy)
    our scan_bencode_value returns pointer to the raw data start (not prefixed len)
    vlen currently holds the number of bytes in the value (for strings)
    */

    // determine piece hash length:
    if (vlen % 32 == 0) storage->piece_hash_len = 32;
    else if (vlen % 20 == 0) storage->piece_hash_len = 20;
    else { fprintf(stderr, "[storage] unsupported pieces length (%zu)\n", vlen); return -1; }
    storage->num_pieces = (uint32_t)(vlen / storage->piece_hash_len);
    storage->pieces_hashes = malloc((size_t)storage->num_pieces * storage->piece_hash_len);
    if (!storage->pieces_hashes) {
        fprintf(stderr, "[DEBUG] storage_init_from_info: Failed to malloc pieces_hashes\n");
        return -1;
    }
    memcpy(storage->pieces_hashes, p, vlen);

    // find length (single-file)
    // fprintf(stderr, "[DEBUG] storage_init_from_info: Before find_key for length\n");
    p = find_key(info_buf, info_len, "length", &start, &vlen);
    if (!p) { fprintf(stderr, "[storage] missing length (multi-file not supported in this minimal impl)\n"); return -1; }
    // fprintf(stderr, "[DEBUG] storage_init_from_info: After find_key for length\n");
    if (p[0] != 'i') { fprintf(stderr, "[DEBUG] storage_init_from_info: length not integer\n"); return -1; }
    i = 1; j = 0;
    while (i < vlen && p[i] != 'e' && j+1 < sizeof(tmp)) tmp[j++] = p[i++]; tmp[j]=0;
    storage->total_length = (uint64_t)atoll(tmp);
    // storage path
    make_storage_path(storage, storage->name);

    // ensure file exists and is total_length bytes (create if missing)
    // fprintf(stderr, "[DEBUG] storage_init_from_info: Before open storage_path %s\n", storage->storage_path);
    int fd = open(storage->storage_path, O_RDWR | O_CREAT, 0666);
    if (fd < 0) { perror("open storage"); return -1; }
    // fprintf(stderr, "[DEBUG] storage_init_from_info: After open storage_path\n");
    struct stat st;
    if (fstat(fd, &st) == 0) {
        if ((uint64_t)st.st_size < storage->total_length) {
            // fprintf(stderr, "[DEBUG] storage_init_from_info: Truncating file\n");
            if (ftruncate(fd, storage->total_length) != 0) {
                perror("ftruncate");
                close(fd);
                return -1;
            }
        }
    }
    close(fd);

    // init bitfield (all zero -> no pieces)
    size_t bits_bytes = (storage->num_pieces + 7) / 8;
    storage->have_bits = calloc(1, bits_bytes);
    if (!storage->have_bits) {fprintf(stderr, "[DEBUG] storage_init_from_info: Failed to calloc have_bits\n");  return -1};
    fprintf(stderr, "[storage] init: pieces=%u piece_len=%u piece_hash_len=%zu total=%llu path=%s\n",
            storage->num_pieces, storage->piece_len, storage->piece_hash_len, (unsigned long long)storage->total_length,
            storage->storage_path);
    //fprintf(stderr, "[DEBUG] storage_init_from_info: Exit success\n");
    return 0;
}

void storage_free(storage_t *s) {
    if (!s) return;
    free(s->pieces_hashes); s->pieces_hashes = NULL;
    free(s->have_bits); s->have_bits = NULL;
}

/* bitfiled getter */
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
    off_t offset = (off_t)index * s->piece_len + begin;
    int fd = open(s->storage_path, O_RDONLY);
    if (fd < 0) return -1;
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) { close (fd); return -1; }
    ssize_t r = read(fd, buf, length);
    close(fd);
    return (r==(ssize_t)length) ? 0 : -1;
}

static void set_have_bit(storage_t *s, uint32_t index) {
    size_t byte = index / 8;
    size_t bit = 7 - (index % 8);
    s->have_bits[byte] |= (1u << bit);
}
static int get_have_bit(storage_t *s uint32_t index) {
    size_t byte = index / 8;
    size_t bit = 7 - (index % 8);
    return (s->have_bits[byte] >> bit) & 1;
}

static int verify_piece_sha256(storage_t *s, uint32_t index) {
    uint32_t psize = storage_piece_size(s, index);
    unsigned char *buf = malloc(psize);
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
int storage_write_block_and_check(storage_t *s, uint32_t index, uint32_t begin, const void *buf, uint32_t length) {
    if (index >= s->num_pieces) return -1;
    uint32_t psize = storage_piece_size(s, index);
    if (begin + length > psize) return -1;
    off_t offset = (off_t)index * s->piece_len + begin;
    int fd = open(s->storage_path, O_RDWR);
    if (fd < 0) return -1;
    if (lseek(fd, offset, SEEK_SET) == (off_t)-1) { close(fd); return -1; }
    ssize_t w = write(fd, buf, length);
    if (w != (ssize_t)length) { close(fd); return -1; }
    close(fd);

    // Check if all bytes of piece are non-zero? Simpler: always verify when write occurs for now.
    
    // TODO: track which blocks are present. For simplicity, verify entire piece now.

    int ver = verify_piece_sha256(s, index);
    if (ver == 0) {
        set_have_bit(s, index);
        return 0;
    } else {
        return -2; 
    }
}

int storage_is_piece_complete(storage_t *s, uint32_t index) {
    if (index >= s->num_pieces) return 0;
    return get_have_bit(s, index);
}