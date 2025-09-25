// bt_peer.c
// Simple two-peer file transfer: seed <-> receive, length-prefixed frames,
// per-chunk SHA-256 verification.
// Build: cc -O2 -std=c11 bt_peer.c -o bt -lcrypto -pthread

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---------------- config & constants ---------------- */
#define DEFAULT_CHUNK_SIZE (256 * 1024) // 256 KiB
#define BACKLOG 8

// Frame types (1 byte)
enum {
    T_HELLO = 1,
    T_MANIFEST = 2,
    T_REQ_CHUNK = 3,
    T_CHUNK_DATA = 4,
    T_ACK = 5,
    T_NACK = 6,
    T_GOODBYE = 7
};

/* ---------------- helpers: readn/writen, htonll ---------------- */

static ssize_t readn(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t left = n;
    while (left) {
        ssize_t r = recv(fd, p, left, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return (ssize_t)(n - left); // EOF or closed
        p += r; left -= r;
    }
    return (ssize_t)n;
}

static ssize_t writen(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t left = n;
    while (left) {
        ssize_t w = send(fd, p, left, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w; left -= (size_t)w;
    }
    return (ssize_t)n;
}

static uint64_t htonll_u64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl((uint32_t)(v & 0xFFFFFFFFULL)) << 32) | htonl((uint32_t)(v >> 32));
#else
    return v;
#endif
}
static uint64_t ntohll_u64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)ntohl((uint32_t)(v & 0xFFFFFFFFULL)) << 32) | ntohl((uint32_t)(v >> 32));
#else
    return v;
#endif
}

/* ---------------- utility: hex print ---------------- */
static void hexprint(const unsigned char *b, size_t n, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        out[2*i]   = hex[(b[i] >> 4) & 0xF];
        out[2*i+1] = hex[b[i] & 0xF];
    }
    out[2*n] = 0;
}

/* ---------------- manifest structures ---------------- */
typedef struct {
    uint32_t idx;
    unsigned char sha256[32];
} piece_meta_t;

typedef struct {
    uint64_t file_size;
    uint32_t chunk_size;
    uint32_t n_chunks;
    piece_meta_t *pieces; // length n_chunks
} manifest_t;

/* ---------------- sha256 helper ---------------- */
static void sha256_buf(const unsigned char *buf, size_t len, unsigned char out32[32]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf, len);
    SHA256_Final(out32, &ctx);
}

/* ---------------- frame helpers ----------------
   frame: [4-byte BE length L][1-byte type][L-1 bytes payload]
   length counts type+payload; so minimum L==1 (type only)
*/

/* send frame with a small payload buffer */
static int send_frame(int fd, uint8_t type, const unsigned char *payload, uint32_t payload_len) {
    uint32_t L = payload_len + 1; // type + payload
    uint32_t L_be = htonl(L);
    unsigned char header[5];
    memcpy(header, &L_be, 4);
    header[4] = type;
    if (writen(fd, header, 5) != 5) return -1;
    if (payload_len > 0) {
        if (writen(fd, payload, payload_len) != (ssize_t)payload_len) return -1;
    }
    return 0;
}

/* read a frame: returns type in *typep, allocates payload (caller free) and payload_len */
static int recv_frame(int fd, uint8_t *typep, unsigned char **payload_out, uint32_t *payload_len_out) {
    uint32_t L_be;
    ssize_t r = readn(fd, &L_be, 4);
    if (r != 4) return -1;
    uint32_t L = ntohl(L_be);
    if (L == 0) return -1; // invalid
    unsigned char t;
    r = readn(fd, &t, 1);
    if (r != 1) return -1;
    uint32_t payload_len = L - 1;
    unsigned char *payload = NULL;
    if (payload_len > 0) {
        payload = malloc(payload_len);
        if (!payload) return -1;
        r = readn(fd, payload, payload_len);
        if (r != (ssize_t)payload_len) { free(payload); return -1; }
    }
    *typep = t;
    *payload_out = payload;
    *payload_len_out = payload_len;
    return 0;
}

/* ---------------- manifest creation (seed) ---------------- */
static int build_manifest(const char *path, uint32_t chunk_size, manifest_t *m) {
    struct stat st;
    if (stat(path, &st) != 0) { perror("stat"); return -1; }
    uint64_t filesize = (uint64_t)st.st_size;
    uint32_t n_chunks = (uint32_t)((filesize + chunk_size - 1) / chunk_size);
    piece_meta_t *pieces = calloc(n_chunks, sizeof(piece_meta_t));
    if (!pieces) { perror("calloc"); return -1; }

    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); free(pieces); return -1; }

    unsigned char *buf = malloc(chunk_size);
    if (!buf) { perror("malloc"); fclose(f); free(pieces); return -1; }

    for (uint32_t i = 0; i < n_chunks; ++i) {
        uint64_t off = (uint64_t)i * chunk_size;
        size_t want = (off + chunk_size <= filesize) ? chunk_size : (size_t)(filesize - off);
        if (fseeko(f, (off_t)off, SEEK_SET) != 0) { perror("fseeko"); free(buf); fclose(f); free(pieces); return -1; }
        size_t r = fread(buf, 1, want, f);
        if (r != want) { perror("fread"); free(buf); fclose(f); free(pieces); return -1; }
        sha256_buf(buf, want, pieces[i].sha256);
        pieces[i].idx = i;
    }
    free(buf);
    fclose(f);

    m->file_size = filesize;
    m->chunk_size = chunk_size;
    m->n_chunks = n_chunks;
    m->pieces = pieces;
    return 0;
}

/* free manifest */
static void free_manifest(manifest_t *m) {
    if (m->pieces) free(m->pieces);
    m->pieces = NULL;
}

/* ---------------- seed: handle single client connection ----------------
   protocol:
   - send MANIFEST
   - then loop: read frames; on REQ_CHUNK (uint32 idx), send CHUNK_DATA with:
       uint32 idx_be | uint32 data_len_be | <data> | 32-byte sha256
*/
typedef struct {
    const char *file_path;
    manifest_t manifest;
    int corrupt_chunk; // -1 no corruption, otherwise chunk idx to flip a byte
} seed_ctx_t;

static int send_manifest_frame(int cli_fd, manifest_t *m) {
    // payload: file_size(8) + chunk_size(4) + n_chunks(4) + (n_chunks * 32 bytes)
    uint32_t hashes_len = m->n_chunks * 32;
    uint32_t payload_len = 8 + 4 + 4 + hashes_len;
    unsigned char *buf = malloc(payload_len);
    if (!buf) return -1;
    uint64_t fs_be = htonll_u64(m->file_size);
    memcpy(buf, &fs_be, 8);
    uint32_t cs_be = htonl(m->chunk_size);
    memcpy(buf+8, &cs_be, 4);
    uint32_t nc_be = htonl(m->n_chunks);
    memcpy(buf+12, &nc_be, 4);
    unsigned char *p = buf + 16;
    for (uint32_t i = 0; i < m->n_chunks; ++i) {
        memcpy(p, m->pieces[i].sha256, 32);
        p += 32;
    }
    int rc = send_frame(cli_fd, (uint8_t)T_MANIFEST, buf, payload_len);
    free(buf);
    return rc;
}
__attribute__((unused))
static void *seed_client_thread(void *arg) {
    // arg is pointer to seed_ctx_t (malloced), which is shared readonly
    seed_ctx_t *ctx = (seed_ctx_t *)arg;
    // For simple demo, we create a listening socket in main and pass fd; here assume client fd passed in ctx->file_path? -> We'll instead pass fd via separate small struct. (But for simplicity we pass file descriptor via global init in main below.)
    // We'll not reuse thread model; in this single file we call seed_client_thread logic inline.
    (void)ctx;
    return NULL;
}

/* serve one client on cli_fd */
static int serve_client_once(int cli_fd, seed_ctx_t *ctx) {
    // send manifest
    if (send_manifest_frame(cli_fd, &ctx->manifest) != 0) {
        fprintf(stderr, "failed to send manifest\n");
        return -1;
    }
    // loop for requests
    while (1) {
        uint8_t type;
        unsigned char *payload = NULL;
        uint32_t payload_len = 0;
        if (recv_frame(cli_fd, &type, &payload, &payload_len) != 0) {
            fprintf(stderr, "client closed or error\n");
            if (payload) free(payload);
            return -1;
        }
        if (type == T_REQ_CHUNK) {
            if (payload_len != 4) { free(payload); continue; }
            uint32_t idx_be;
            memcpy(&idx_be, payload, 4);
            uint32_t idx = ntohl(idx_be);
            free(payload);

            if (idx >= ctx->manifest.n_chunks) {
                // send NACK
                uint32_t be = htonl(idx);
                send_frame(cli_fd, T_NACK, (unsigned char *)&be, 4);
                continue;
            }
            // read the chunk from disk
            uint64_t off = (uint64_t)idx * ctx->manifest.chunk_size;
            size_t want = (off + ctx->manifest.chunk_size <= ctx->manifest.file_size) ? ctx->manifest.chunk_size : (size_t)(ctx->manifest.file_size - off);
            unsigned char *buf = malloc(want);
            if (!buf) return -1;
            FILE *f = fopen(ctx->file_path, "rb");
            if (!f) { free(buf); return -1; }
            if (fseeko(f, (off_t)off, SEEK_SET) != 0) { perror("fseeko"); fclose(f); free(buf); return -1; }
            size_t r = fread(buf, 1, want, f);
            fclose(f);
            if (r != want) { fprintf(stderr, "short read\n"); free(buf); return -1; }

            // optional corruption injection (flip one byte)
            if (ctx->corrupt_chunk >= 0 && (int)idx == ctx->corrupt_chunk) {
                // flip lowest bit in first byte:
                buf[0] ^= 1;
                // clear so we corrupt only once
                ctx->corrupt_chunk = -1;
                fprintf(stderr, "corrupted chunk %u intentionally for test\n", idx);
            }

            unsigned char sha[32];
            sha256_buf(buf, want, sha);

            // build payload: idx_be(4) + data_len_be(4) + data + sha[32]
            uint32_t total_payload = 4 + 4 + (uint32_t)want + 32;
            unsigned char *pl = malloc(total_payload);
            if (!pl) { free(buf); return -1; }
            uint32_t idx_be2 = htonl(idx);
            uint32_t dl_be = htonl((uint32_t)want);
            memcpy(pl, &idx_be2, 4);
            memcpy(pl+4, &dl_be, 4);
            memcpy(pl+8, buf, want);
            memcpy(pl+8+want, sha, 32);

            int rc = send_frame(cli_fd, (uint8_t)T_CHUNK_DATA, pl, total_payload);
            free(pl);
            free(buf);
            if (rc != 0) {
                fprintf(stderr, "send_frame failed\n");
                return -1;
            }
            // now optional: wait for ACK/NACK for this chunk (not mandatory)
            unsigned char *ack_payload = NULL;
            uint8_t atype;
            uint32_t acklen;
            if (recv_frame(cli_fd, &atype, &ack_payload, &acklen) != 0) { free(ack_payload); return -1; }
            if (atype == T_ACK) {
                // good
                free(ack_payload);
                continue;
            } else if (atype == T_NACK) {
                // client says bad; continue loop and client will re-request
                free(ack_payload);
                continue;
            } else {
                // ignore others
                free(ack_payload);
                continue;
            }
        } else if (type == T_GOODBYE) {
            free(payload);
            break;
        } else {
            // ignore
            free(payload);
            continue;
        }
    }
    return 0;
}

/* ---------------- receiver (client) ----------------
   connect to seed, read manifest, request chunk 0..n-1 in sequence,
   verify per-chunk sha256, write to file offset, send ACK/NACK.
*/
static int receiver_run(const char *connect_hostport, const char *out_path, int chunk_size_override) {
    // parse host:port
    char host[256]; char port[64];
    const char *p = strchr(connect_hostport, ':');
    if (!p) { fprintf(stderr, "connect must be host:port\n"); return -1; }
    size_t hlen = p - connect_hostport;
    if (hlen >= sizeof(host)) return -1;
    memcpy(host, connect_hostport, hlen); host[hlen] = 0;
    strncpy(port, p+1, sizeof(port)-1); port[sizeof(port)-1]=0;

    // connect
    struct addrinfo hints={0}, *res;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(host, port, &hints, &res) != 0) { perror("getaddrinfo"); return -1; }
    int s = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(s); s = -1;
    }
    freeaddrinfo(res);
    if (s < 0) { perror("connect"); return -1; }

    // read manifest frame
    uint8_t type;
    unsigned char *payload = NULL;
    uint32_t payload_len = 0;
    if (recv_frame(s, &type, &payload, &payload_len) != 0) { fprintf(stderr, "recv manifest failed\n"); return -1; }
    if (type != T_MANIFEST) { fprintf(stderr, "expected manifest\n"); free(payload); return -1; }
    if (payload_len < 16) { free(payload); return -1; }
    uint64_t fs_be; memcpy(&fs_be, payload, 8); uint64_t file_size = ntohll_u64(fs_be);
    uint32_t cs_be; memcpy(&cs_be, payload+8, 4); uint32_t chunk_size = ntohl(cs_be);
    uint32_t nc_be; memcpy(&nc_be, payload+12, 4); uint32_t n_chunks = ntohl(nc_be);
    if (chunk_size_override > 0) chunk_size = (uint32_t)chunk_size_override;

    if (payload_len != 16 + n_chunks*32) { fprintf(stderr, "manifest size mismatch\n"); free(payload); return -1; }

    piece_meta_t *pieces = calloc(n_chunks, sizeof(piece_meta_t));
    unsigned char *pcur = payload + 16;
    for (uint32_t i = 0; i < n_chunks; ++i) {
        pieces[i].idx = i;
        memcpy(pieces[i].sha256, pcur + i*32, 32);
    }
    free(payload);

    printf("Manifest received: size=%" PRIu64 " chunk_size=%u n_chunks=%u\n", file_size, chunk_size, n_chunks);

    // prepare output file (sparse write: create file of right size)
    FILE *out = fopen(out_path, "wb+");
    if (!out) { perror("fopen out"); free(pieces); close(s); return -1; }
    if (file_size > 0) {
        if (fseeko(out, (off_t)(file_size - 1), SEEK_SET) != 0) { perror("fseeko out"); fclose(out); free(pieces); close(s); return -1; }
        if (fwrite("\0", 1, 1, out) != 1) { perror("fwrite out"); fclose(out); free(pieces); close(s); return -1; }
        fflush(out);
    }

    // request loop
    unsigned char *buf = malloc(chunk_size);
    if (!buf) { perror("malloc"); fclose(out); free(pieces); close(s); return -1; }

    for (uint32_t idx = 0; idx < n_chunks; ++idx) {
        // send REQ_CHUNK
        uint32_t idx_be = htonl(idx);
        if (send_frame(s, T_REQ_CHUNK, (unsigned char *)&idx_be, 4) != 0) { fprintf(stderr, "send req failed\n"); break; }

        // recv CHUNK_DATA
        uint8_t rtype;
        unsigned char *rpl = NULL;
        uint32_t rlen = 0;
        if (recv_frame(s, &rtype, &rpl, &rlen) != 0) { fprintf(stderr, "recv chunk failed\n"); break; }
        if (rtype != T_CHUNK_DATA) { fprintf(stderr, "expected CHUNK_DATA type=%u\n", rtype); free(rpl); break; }

        if (rlen < 8 + 32) { fprintf(stderr, "chunk payload too small\n"); free(rpl); break; }
        uint32_t ridx_be; memcpy(&ridx_be, rpl, 4); uint32_t ridx = ntohl(ridx_be);
        uint32_t dlen_be; memcpy(&dlen_be, rpl+4, 4); uint32_t dlen = ntohl(dlen_be);
        if (ridx != idx) { fprintf(stderr, "chunk idx mismatch expected %u got %u\n", idx, ridx); free(rpl); break; }
        if (rlen != 8 + dlen + 32) { fprintf(stderr, "unexpected chunk payload length\n"); free(rpl); break; }
        unsigned char *data = rpl + 8;
        unsigned char *sha_recv = rpl + 8 + dlen;

        // compute sha256 on data
        unsigned char sha_calc[32];
        sha256_buf(data, dlen, sha_calc);

        if (memcmp(sha_calc, sha_recv, 32) != 0) {
            // mismatch
            fprintf(stderr, "chunk %u sha mismatch -> request again\n", idx);
            uint32_t be = htonl(idx);
            send_frame(s, T_NACK, (unsigned char *)&be, 4);
            free(rpl);
            idx--; // retry same index
            continue;
        } else {
            // verify against manifest too
            if (memcmp(sha_calc, pieces[idx].sha256, 32) != 0) {
                fprintf(stderr, "chunk %u does not match manifest -> abort\n", idx);
                free(rpl); break;
            }
            // write at offset
            off_t off = (off_t)idx * chunk_size;
            if (fseeko(out, off, SEEK_SET) != 0) { perror("fseeko write"); free(rpl); break; }
            if (fwrite(data, 1, dlen, out) != dlen) { perror("fwrite chunk"); free(rpl); break; }
            fflush(out);
            // send ACK
            uint32_t be = htonl(idx);
            send_frame(s, T_ACK, (unsigned char *)&be, 4);
            free(rpl);
            continue;
        }
    }

    // cleanup
    free(buf);
    fclose(out);
    // final file sha check (optional)
    // compute full-file sha256 for final verification
    {
        FILE *f = fopen(out_path, "rb");
        if (f) {
            SHA256_CTX ctx; SHA256_Init(&ctx);
            unsigned char tmp[65536];
            size_t r;
            while ((r = fread(tmp,1,sizeof(tmp), f)) > 0) SHA256_Update(&ctx, tmp, r);
            unsigned char whole[32]; SHA256_Final(whole, &ctx);
            char hex[65]; hexprint(whole, 32, hex);
            printf("Receiver: final file SHA256: %s\n", hex);
            fclose(f);
        }
    }

    free(pieces);
    close(s);
    return 0;
}

/* ---------------- seed main loop ----------------
   start listening, build manifest, accept one client then serve.
*/
static int seed_run(const char *port_s, const char *file_path, uint32_t chunk_size, int corrupt_chunk) {
    // build manifest
    manifest_t m = {0};
    if (build_manifest(file_path, chunk_size, &m) != 0) { fprintf(stderr, "failed manifest\n"); return -1; }
    printf("Seed: built manifest file_size=%" PRIu64 " chunk_size=%u n_chunks=%u\n", m.file_size, m.chunk_size, m.n_chunks);
    // start listening
    struct addrinfo hints={0}, *res;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(NULL, port_s, &hints, &res) != 0) { perror("getaddrinfo"); free_manifest(&m); return -1; }
    int srv = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        srv = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (srv < 0) continue;
        int yes = 1; setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(srv, ai->ai_addr, ai->ai_addrlen) == 0 && listen(srv, BACKLOG) == 0) break;
        close(srv); srv = -1;
    }
    freeaddrinfo(res);
    if (srv < 0) { perror("bind/listen"); free_manifest(&m); return -1; }
    printf("Seed listening on port %s\n", port_s);

    // accept and serve single client (for simplicity)
    struct sockaddr_storage ss; socklen_t sl = sizeof(ss);
    int cli = accept(srv, (struct sockaddr *)&ss, &sl);
    if (cli < 0) { perror("accept"); close(srv); free_manifest(&m); return -1; }
    seed_ctx_t ctx = { .file_path = file_path, .manifest = m, .corrupt_chunk = corrupt_chunk };
    // serve client inline
    int rc = serve_client_once(cli, &ctx);
    close(cli);
    close(srv);
    free_manifest(&m);
    return rc;
}

/* ---------------- CLI simple parser & main ---------------- */
static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s peer --mode seed --port PORT --file FILE [--chunk-size BYTES] [--corrupt-chunk IDX]\n"
        "  %s peer --mode receive --connect HOST:PORT --out OUTFILE [--chunk-size BYTES]\n", prog, prog);
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }
    if (strcmp(argv[1], "peer") != 0) { usage(argv[0]); return 1; }

    // minimal argument parsing
    const char *mode = NULL;
    const char *port = NULL;
    const char *file = NULL;
    const char *connect = NULL;
    const char *out = NULL;
    uint32_t chunk_size = DEFAULT_CHUNK_SIZE;
    int corrupt_chunk = -1;

    for (int i = 2; i < argc; ++i) {
        if (strcmp(argv[i], "--mode") == 0 && i+1<argc) mode = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i+1<argc) port = argv[++i];
        else if (strcmp(argv[i], "--file") == 0 && i+1<argc) file = argv[++i];
        else if (strcmp(argv[i], "--connect") == 0 && i+1<argc) connect = argv[++i];
        else if (strcmp(argv[i], "--out") == 0 && i+1<argc) out = argv[++i];
        else if (strcmp(argv[i], "--chunk-size") == 0 && i+1<argc) chunk_size = (uint32_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--corrupt-chunk") == 0 && i+1<argc) corrupt_chunk = atoi(argv[++i]);
        else {
            fprintf(stderr, "Unknown arg: %s\n", argv[i]); usage(argv[0]); return 1;
        }
    }

    if (!mode) { fprintf(stderr, "--mode required\n"); usage(argv[0]); return 1; }

    if (strcmp(mode, "seed") == 0) {
        if (!port || !file) { fprintf(stderr, "--port and --file required for seed\n"); usage(argv[0]); return 1; }
        return seed_run(port, file, chunk_size, corrupt_chunk);
    } else if (strcmp(mode, "receive") == 0) {
        if (!connect || !out) { fprintf(stderr, "--connect and --out required for receive\n"); usage(argv[0]); return 1; }
        return receiver_run(connect, out, chunk_size);
    } else {
        fprintf(stderr, "unknown mode\n"); usage(argv[0]); return 1;
    }
    return 0;
}
