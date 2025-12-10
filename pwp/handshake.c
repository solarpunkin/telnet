#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "peer_wire.h"
#include "storage.h"
#include "bencode.h"   // update the path
/* ---------------- helpers: readn/writen ---------------- */
static ssize_t readn(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t left = n;
    while (left) {
        ssize_t r = recv(fd, p, left, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return (ssize_t)(n - left);
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

/* global storage backend (initialized from torrent info) */
static storage_t STORAGE;

/* ---------------- find the exact bencoded "info" slice in a .torrent file ----------------
   We must SHA256 the exact bencoded bytes for the "info" dictionary.
   Approach: find the substring "4:info" and then parse the bencoded value that follows
   by walking the structure (handling strings, ints, lists, dicts) until it's balanced.
*/
static int find_info_slice(const unsigned char *buf, size_t len, size_t *out_start, size_t *out_end) {
    // search for "4:info"
    const char needle[] = "4:info";
    size_t nlen = strlen(needle);
    for (size_t i = 0; i + nlen <= len; ++i) {
        if (memcmp(buf + i, needle, nlen) == 0) {
            // value starts at i + nlen
            size_t pos = i + nlen;
            if (pos >= len) return -1;
            // value must be a bencoded value; parse it and find end pos (pos..end-1)
            // We'll implement a stackless walker:
            size_t p = pos;
            int depth = 0;
            bool started = false;
            while (p < len) {
                unsigned char c = buf[p];
                if (!started) {
                    // first token must start the info value
                    if (c == 'd' || c == 'l') { depth = 1; started = true; p++; continue; }
                    else if (c == 'i') { // integer: read until 'e'
                        size_t q = p+1;
                        while (q < len && buf[q] != 'e') q++;
                        if (q >= len) return -1;
                        *out_start = p;
                        *out_end = q+1;
                        return 0;
                    } else if (c >= '0' && c <= '9') {
                        // string: parse length ":" then skip bytes
                        size_t q = p;
                        while (q < len && buf[q] != ':') q++;
                        if (q >= len) return -1;
                        // parse len
                        char tmp[32]; size_t m = q - p;
                        if (m >= sizeof(tmp)) return -1;
                        memcpy(tmp, buf + p, m); tmp[m] = 0;
                        long sl = atol(tmp);
                        size_t start = q + 1;
                        if (start + (size_t)sl > len) return -1;
                        *out_start = p;
                        *out_end = start + (size_t)sl;
                        return 0;
                    } else {
                        return -1;
                    }
                } else {
                    // We are inside a list/dict; need to walk tokens until depth==0
                    if (c == 'd' || c == 'l') { depth++; p++; continue; }
                    else if (c == 'e') {
                        depth--; p++;
                        if (depth == 0) {
                            *out_start = pos;
                            *out_end = p;
                            return 0;
                        }
                        continue;
                    } else if (c == 'i') {
                        // integer, skip until 'e'
                        size_t q = p+1;
                        while (q < len && buf[q] != 'e') q++;
                        if (q >= len) return -1;
                        p = q+1;
                        continue;
                    } else if (c >= '0' && c <= '9') {
                        // string: parse len and skip
                        size_t q = p;
                        while (q < len && buf[q] != ':') q++;
                        if (q >= len) return -1;
                        char tmp[32]; size_t m = q - p;
                        if (m >= sizeof(tmp)) return -1;
                        memcpy(tmp, buf + p, m); tmp[m] = 0;
                        long sl = atol(tmp);
                        size_t start = q + 1;
                        if (start + (size_t)sl > len) return -1;
                        p = start + (size_t)sl;
                        continue;
                    } else {
                        return -1;
                    }
                }
            }
            return -1;
        }
    }
    return -1;
}

/* compute SHA256 over a buffer slice; output first 20 bytes truncated digest into out20 */
static int compute_info_hash_sha256_truncated(const unsigned char *buf, size_t start, size_t end, unsigned char out20[20]) {
    if (end <= start) return -1;
    unsigned char digest[32];
    unsigned int dlen;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, buf + start, end - start);
    EVP_DigestFinal_ex(ctx, digest, &dlen);
    EVP_MD_CTX_free(ctx);
    memcpy(out20, digest, 20); // truncation policy
    return 0;
}

/* ---------------- peer manager ---------------- */

typedef struct peer_entry {
    unsigned char peer_id[20];
    char ip[INET6_ADDRSTRLEN];
    uint16_t port;
    int choke;       // 1=choked, 0=unchoked
    int interested;  // 1=interested, 0=not
    time_t last_seen;
    struct peer_entry *next;
} peer_entry_t;

typedef struct {
    peer_entry_t *head;
    pthread_mutex_t lock;
} peer_manager_t;

static peer_manager_t PM;

static void pm_init(peer_manager_t *pm) {
    pm->head = NULL;
    pthread_mutex_init(&pm->lock, NULL);
}

static void pm_add_or_update(peer_manager_t *pm, const unsigned char peer_id[20],
                             const char *ip, uint16_t port) {
    pthread_mutex_lock(&pm->lock);
    peer_entry_t *p = pm->head;
    while (p) {
        if (p->port == port && strcmp(p->ip, ip) == 0 && memcmp(p->peer_id, peer_id, 20) == 0) {
            p->last_seen = time(NULL);
            pthread_mutex_unlock(&pm->lock);
            return;
        }
        p = p->next;
    }
    // add
    peer_entry_t *n = calloc(1, sizeof(peer_entry_t));
    memcpy(n->peer_id, peer_id, 20);
    strncpy(n->ip, ip, sizeof(n->ip)-1);
    n->port = port;
    n->choke = 1; // default choked
    n->interested = 0;
    n->last_seen = time(NULL);
    n->next = pm->head;
    pm->head = n;
    pthread_mutex_unlock(&pm->lock);
    char pidhex[41]; for (int i=0;i<20;i++) sprintf(pidhex+2*i, "%02x", n->peer_id[i]); pidhex[40]=0;
    fprintf(stderr, "[PM] added peer %s:%u id=%s\n", n->ip, n->port, pidhex);
}

// set state by peer_id
static void pm_set_choke(peer_manager_t *pm, const unsigned char peer_id[20], int choke){
    pthread_mutex_lock(&pm->lock);
    peer_entry_t *p = pm->head;
    while (p){
        if (memcmp(p->peer_id, peer_id, 20) == 0){
            p->choke = choke ? 1 : 0;
            p->last_seen = time(NULL);
            break;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&pm->lock);
}

static void pm_set_interested(peer_manager_t *pm, const unsigned char peer_id[20], int interested){
    pthread_mutex_lock(&pm->lock);
    peer_entry_t *p = pm->head;
    while (p){
        if (memcmp(p->peer_id, peer_id, 20) == 0){
            p->interested = interested ? 1 : 0;
            p->last_seen = time(NULL);
            break;
        }
        p = p->next;
    }
    pthread_mutex_unlock(&pm->lock);
}

static void pm_log_all(peer_manager_t *pm) {
    pthread_mutex_lock(&pm->lock);
    peer_entry_t *p = pm->head;
    fprintf(stderr, "---- peer-manager dump ----\n");
    while (p) {
        char pidhex[41]; for (int i=0;i<20;i++) sprintf(pidhex+2*i, "%02x", p->peer_id[i]); pidhex[40]=0;
        fprintf(stderr, "peer %s:%u id=%s choke=%d interested=%d last_seen=%ld\n",
                p->ip, p->port, pidhex, p->choke, p->interested, (long)p->last_seen);
        p = p->next;
    }
    fprintf(stderr, "---------------------------\n");
    pthread_mutex_unlock(&pm->lock);
}

/* ---------------- handshake framing ----------------
   Handshake layout:
   <pstrlen><pstr><reserved(8)><info_hash(20)><peer_id(20)>
   pstrlen is a single byte length of pstr.
   pstr is typically "BitTorrent protocol" or a custom string.
*/

#define HANDSHAKE_PSTR "BitTorrent protocol"
#define HANDSHAKE_PSTR_LEN (sizeof(HANDSHAKE_PSTR)-1)
#define HANDSHAKE_RESERVED_LEN 8
#define HANDSHAKE_INFOHASH_LEN 20
#define HANDSHAKE_PEERID_LEN 20
#define HANDSHAKE_TOTAL_LEN (1 + HANDSHAKE_PSTR_LEN + HANDSHAKE_RESERVED_LEN + HANDSHAKE_INFOHASH_LEN + HANDSHAKE_PEERID_LEN)

/* send a handshake - blocking; returns 0 on success */
static int send_handshake(int fd, const unsigned char info_hash[20], const unsigned char peer_id[20]) {
    unsigned char buf[HANDSHAKE_TOTAL_LEN];
    size_t pos = 0;
    buf[pos++] = (unsigned char)HANDSHAKE_PSTR_LEN;
    memcpy(buf + pos, HANDSHAKE_PSTR, HANDSHAKE_PSTR_LEN); pos += HANDSHAKE_PSTR_LEN;
    memset(buf + pos, 0, HANDSHAKE_RESERVED_LEN); pos += HANDSHAKE_RESERVED_LEN;
    memcpy(buf + pos, info_hash, HANDSHAKE_INFOHASH_LEN); pos += HANDSHAKE_INFOHASH_LEN;
    memcpy(buf + pos, peer_id, HANDSHAKE_PEERID_LEN); pos += HANDSHAKE_PEERID_LEN;
    if (writen(fd, buf, pos) != (ssize_t)pos) return -1;
    return 0;
}

/* receive a handshake; validate and fill remote peer_id and info_hash; returns 0 on success */
static int recv_handshake(int fd, unsigned char out_info_hash[20], unsigned char out_peer_id[20]) {
    // read pstrlen first
    unsigned char pstrlen;
    if (readn(fd, &pstrlen, 1) != 1) return -1;
    if (pstrlen == 0 || pstrlen > 255) return -1;
    // read pstr
    char pstr[256];
    if (readn(fd, pstr, pstrlen) != (ssize_t)pstrlen) return -1;
    pstr[pstrlen] = 0;
    // read reserved
    unsigned char reserved[HANDSHAKE_RESERVED_LEN];
    if (readn(fd, reserved, HANDSHAKE_RESERVED_LEN) != HANDSHAKE_RESERVED_LEN) return -1;
    // read info_hash
    if (readn(fd, out_info_hash, HANDSHAKE_INFOHASH_LEN) != HANDSHAKE_INFOHASH_LEN) return -1;
    if (readn(fd, out_peer_id, HANDSHAKE_PEERID_LEN) != HANDSHAKE_PEERID_LEN) return -1;
    return 0;
}

/* helper: send HAVE (message id = 4) */
static int send_have(int fd, uint32_t index) {
    uint32_t be_len = htonl(1 + 4); /* id + 4-byte index */
    unsigned char buf[9];
    memcpy(buf, &be_len, 4);
    buf[4] = 4; /* HAVE */
    uint32_t be_index = htonl(index);
    memcpy(buf + 5, &be_index, 4);
    return writen(fd, buf, sizeof(buf)) == (ssize_t)sizeof(buf) ? 0 : -1;
}

/* ---------------- message framing and helpers ---------------- */

static int send_keepalive(int fd){
    uint32_t z = htonl(0);
    return writen(fd, &z, 4) == 4 ? 0 : -1;
}
static int send_simple_msg(int fd, unsigned char id) {
    uint32_t len = htonl(1);
    unsigned char buf[5];
    memcpy(buf, &len, 4);
    buf[4] = id;
    return writen(fd, buf, 5) == 5 ? 0 : -1;
}

static int send_choke(int fd){ return send_simple_msg(fd, 0); }
static int send_unchoke(int fd){ return send_simple_msg(fd, 1); }
static int send_interested(int fd){ return send_simple_msg(fd, 2); }
static int send_not_interested(int fd){ return send_simple_msg(fd, 3); }
// send have (id=4) with 4-byte piece index (b-endian)
//send bitfield (id=5) with payload bytes
static int send_bitfiled(int fd, const unsigned char *payload, size_t payload_len) {
    if (payload_len > 0x7fffffff) return -1;
    uint32_t plen = (uint32_t)(1 + payload_len);
    uint32_t len = htonl(plen);
    if (writen(fd, &len, 4) != 4) return -1;
    unsigned char id = 5;
    if (writen(fd, &id, 1) != 1) return -1;
    if (writen(fd, payload, payload_len) != (ssize_t)payload_len) return -1;
    return 0;
}

// skip payload
static void skip_payload(int fd, uint32_t n) {
    unsigned char tmp[4096];
    while (n) {
        size_t chunk = n > sizeof(tmp) ? sizeof(tmp) : n;
        if (readn(fd, tmp, chunk) != (ssize_t)chunk) return;
        n -= chunk;
    }
}

/* ---------------- server code ---------------- */

typedef struct {
    int client_fd;
    struct sockaddr_storage cliaddr;
    socklen_t cliaddr_len;
    unsigned char info_hash[20];
    unsigned char server_peer_id[20];
    storage_t *storage;
} server_conn_ctx_t;

// handle messages after handshake
static void handle_incoming_message(int fd, unsigned char msg_id, uint32_t payload_len, unsigned char *peerid, storage_t *storage) {
    (void)fd;
    // payload_len is length excluding message id; caller must read payload or skip.
    switch (msg_id) {
        case 0: // choke
            pm_set_choke(&PM, peerid, 1);
            fprintf(stderr, "[server] got CHOKE from peer\n");
            break;
        case 1: // unchoke
            pm_set_choke(&PM, peerid, 0);
            fprintf(stderr, "[server] got UNCHOKE from peer\n");
            break;
        case 2: // interested
            pm_set_interested(&PM, peerid, 1);
            fprintf(stderr, "[server] got INTERESTED from peer\n");
            break;
        case 3: // not interested
            pm_set_interested(&PM, peerid, 0);
            fprintf(stderr, "[server] got NOT_INTERESTED from peer\n");
            break;
        case 4: { // have: payload 4 bytes piece index
            fprintf(stderr, "[server] got HAVE (len=%u)\n", payload_len);
            break;
        }
        case 5: // bitfield
            fprintf(stderr, "[server] got BITFIELD len=%u\n", payload_len);
            break;
        default:
            fprintf(stderr, "[server] got UNKNOWN id=%u len=%u\n", msg_id, payload_len);
    }
}



static void *server_conn_thread(void *arg) {
    server_conn_ctx_t *ctx = arg;
    int fd = ctx->client_fd;

    unsigned char remote_info[20], remote_peerid[20];
    if (recv_handshake(fd, remote_info, remote_peerid) != 0) {
        fprintf(stderr, "[server] recv_handshake failed (fd=%d)\n", fd);
        close(fd);
        free(ctx);
        return NULL;
    }
    // verify info_hash matches expected
    if (memcmp(remote_info, ctx->info_hash, 20) != 0) {
        char ourshex[41], theirshex[41];
        for (int i=0;i<20;i++) sprintf(ourshex+2*i, "%02x", ctx->info_hash[i]); ourshex[40]=0;
        for (int i=0;i<20;i++) sprintf(theirshex+2*i, "%02x", remote_info[i]); theirshex[40]=0;
        fprintf(stderr, "[server] info_hash mismatch; ours=%s theirs=%s -> closing\n", ourshex, theirshex);
        close(fd);
        free(ctx);
        return NULL;
    }
    // respond with our handshake
    if (send_handshake(fd, ctx->info_hash, ctx->server_peer_id) != 0) {
        fprintf(stderr, "[server] send_handshake failed\n");
        close(fd); free(ctx); return NULL;
    }

    // register peer in peer manager using sockaddr
    char ipbuf[INET6_ADDRSTRLEN]; uint16_t port = 0;
    if (ctx->cliaddr.ss_family == AF_INET) {
        struct sockaddr_in *s4 = (struct sockaddr_in *)&ctx->cliaddr;
        inet_ntop(AF_INET, &s4->sin_addr, ipbuf, sizeof(ipbuf));
        port = ntohs(s4->sin_port);
    } else {
        struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&ctx->cliaddr;
        inet_ntop(AF_INET6, &s6->sin6_addr, ipbuf, sizeof(ipbuf));
        port = ntohs(s6->sin6_port);
    }
    pm_add_or_update(&PM, remote_peerid, ipbuf, port);

    char pidhex[41]; for (int i=0;i<20;i++) sprintf(pidhex+2*i, "%02x", remote_peerid[i]); pidhex[40]=0;
    fprintf(stderr, "[server] handshake success with %s:%u peerid=%s\n", ipbuf, port, pidhex);

    // keep the connection open for future messages (not implemented here).
    // For demo, sleep a little and close.
    // sleep(1);

    // message loop
    // read length(4), then if 0 keep-alive; else read id + payload
    while (1) {
        uint32_t len_be;
        ssize_t r = readn(fd, &len_be, 4);
        if (r != 4) break;
        uint32_t len = ntohl(len_be);
        if (len == 0) {
            fprintf(stderr, "[server] keep-alive from peer\n");
            continue;
        }
        // read id
        unsigned char id;
        if (readn(fd, &id, 1) != 1) break;
        uint32_t payload_len = len - 1; // len is total payload length for message (excluding initial 4-byte length prefix)

        if (id == 4) { /* HAVE */
            unsigned char have_buf[4];
            if (readn(fd, have_buf, 4) != 4) break; // Read 4-byte piece index
            uint32_t piece_idx = ntohl(*(uint32_t*)have_buf);
            fprintf(stderr, "[server] got HAVE %u\n", piece_idx); // CORRECTED
        }
        else if (id == 6) { /* REQUEST */
            unsigned char reqbuf[12];
            if (readn(fd, reqbuf, 12) != 12) break;
            uint32_t index = ntohl(*(uint32_t*)(reqbuf + 0));
            uint32_t begin = ntohl(*(uint32_t*)(reqbuf + 4));
            uint32_t rlen = ntohl(*(uint32_t*)(reqbuf + 8));
            fprintf(stderr, "[server] got REQUEST idx=%u begin=%u len=%u\n", index, begin, rlen);
            handle_request_msg(fd, remote_peerid, index, begin, rlen, ctx->storage);
        } else if (id == 7) { /* PIECE */
            unsigned char hdr[8];
            if (readn(fd, hdr, 8) != 8) break;
            uint32_t index = ntohl(*(uint32_t*)(hdr + 0));
            uint32_t begin = ntohl(*(uint32_t*)(hdr + 4));
            uint32_t blklen = payload_len - 8;
            unsigned char *blk = malloc(blklen ? blklen : 1);
            if (!blk) { skip_payload(fd, blklen); continue; }
            if (readn(fd, blk, blklen) != (ssize_t)blklen) { free(blk); break; }
            fprintf(stderr, "[server] got PIECE idx=%u begin=%u len=%u\n", index, begin, blklen);
            int rc = handle_piece_msg(fd, remote_peerid, index, begin, blk, blklen, ctx->storage);
            free(blk);
            if (rc == 0 && storage_is_piece_complete(ctx->storage, index)) {
                /* announce HAVE back to peer */
                send_have(fd, index);
            }
        } else if (id == 8) { /* CANCEL */
            unsigned char cbuf[12];
            if (readn(fd, cbuf, 12) != 12) break;
            uint32_t index = ntohl(*(uint32_t*)(cbuf + 0));
            uint32_t begin = ntohl(*(uint32_t*)(cbuf + 4));
            uint32_t rlen = ntohl(*(uint32_t*)(cbuf + 8));
            fprintf(stderr, "[server] got CANCEL idx=%u begin=%u len=%u\n", index, begin, rlen);
            handle_cancel_msg(fd, remote_peerid, index, begin, rlen, ctx->storage);
        } else if (id == 5) { /* BITFIELD */
            unsigned char *bf = malloc(payload_len ? payload_len : 1);
            if (!bf) { skip_payload(fd, payload_len); continue; }
            if (readn(fd, bf, payload_len) != (ssize_t)payload_len) { free(bf); break; }
            fprintf(stderr, "[server] got BITFIELD len=%u\n", payload_len);
            handle_incoming_message(fd, id, payload_len, remote_peerid, ctx->storage);
            free(bf);
        } else {
            /* simple control messages or unknown: read and dispatch */
            if (payload_len) skip_payload(fd, payload_len);
            handle_incoming_message(fd, id, payload_len, remote_peerid, ctx->storage);
        }
    }
    fprintf(stderr, "[server] connection closed for peer %s\n", pidhex);
    close(fd);
    free(ctx);
    return NULL;
}

static int server_run(const char *port_s, const unsigned char info_hash[20], const unsigned char server_peer_id[20]) {
    struct addrinfo hints = {0}, *res, *ai;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    if (getaddrinfo(NULL, port_s, &hints, &res) != 0) { perror("getaddrinfo"); return -1; }
    int listen_fd = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        listen_fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (listen_fd < 0) continue;
        int yes = 1; setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(listen_fd, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(listen_fd); listen_fd = -1;
    }
    freeaddrinfo(res);
    if (listen_fd < 0) { perror("bind failed"); return -1; }
    if (listen(listen_fd, 16) != 0) { perror("listen"); close(listen_fd); return -1; }
    fprintf(stderr, "[server] listening on port %s\n", port_s);

    while (1) {
        struct sockaddr_storage cliaddr; socklen_t clilen = sizeof(cliaddr);
        int cli = accept(listen_fd, (struct sockaddr *)&cliaddr, &clilen);
        if (cli < 0) { if (errno == EINTR) continue; perror("accept"); break; }
        server_conn_ctx_t *ctx = calloc(1, sizeof(*ctx));
        ctx->client_fd = cli;
        memcpy(&ctx->cliaddr, &cliaddr, clilen);
        ctx->cliaddr_len = clilen;
        memcpy(ctx->info_hash, info_hash, 20);
        memcpy(ctx->server_peer_id, server_peer_id, 20);
        ctx->storage = &STORAGE;
        pthread_t tid;
        pthread_create(&tid, NULL, server_conn_thread, ctx);
        pthread_detach(tid);
    }
    close(listen_fd);
    return 0;
}

/* ---------------- client code ---------------- */

static int client_run(const char *hostport, const unsigned char info_hash[20], const unsigned char client_peer_id[20]) {
    // parse host:port
    char host[256], port[64];
    const char *p = strchr(hostport, ':');
    if (!p) { fprintf(stderr, "connect must be host:port\n"); return -1; }
    size_t hlen = p - hostport; if (hlen >= sizeof(host)) return -1;
    memcpy(host, hostport, hlen); host[hlen] = 0;
    strncpy(port, p+1, sizeof(port)-1); port[sizeof(port)-1] = 0;

    struct addrinfo hints = {0}, *res, *ai;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0) { perror("getaddrinfo"); return -1; }
    int s = -1;
    for (ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(s); s = -1;
    }
    freeaddrinfo(res);
    if (s < 0) { perror("connect"); return -1; }

    // send handshake
    if (send_handshake(s, info_hash, client_peer_id) != 0) {
        fprintf(stderr, "[client] send_handshake failed\n"); close(s); return -1;
    }
    // receive handshake
    unsigned char remote_info[20], remote_peerid[20];
    if (recv_handshake(s, remote_info, remote_peerid) != 0) {
        fprintf(stderr, "[client] recv_handshake failed\n"); close(s); return -1;
    }
    // verify
    if (memcmp(remote_info, info_hash, 20) != 0) {
        char mine[41], theirs[41];
        for (int i=0;i<20;i++) sprintf(mine+2*i, "%02x", info_hash[i]); mine[40]=0;
        for (int i=0;i<20;i++) sprintf(theirs+2*i, "%02x", remote_info[i]); theirs[40]=0;
        fprintf(stderr, "[client] info_hash mismatch mine=%s theirs=%s\n", mine, theirs);
        close(s); return -1;
    }
    // register peer into peer manager using remote's address info not readily available here;
    // but we can get the peer's socket name
    struct sockaddr_storage peeraddr; socklen_t plen = sizeof(peeraddr);
    getpeername(s, (struct sockaddr *)&peeraddr, &plen);
    char ipbuf[INET6_ADDRSTRLEN]; uint16_t portn=0;
    if (peeraddr.ss_family == AF_INET) {
        struct sockaddr_in *a = (struct sockaddr_in *)&peeraddr;
        inet_ntop(AF_INET, &a->sin_addr, ipbuf, sizeof(ipbuf));
        portn = ntohs(a->sin_port);
    } else {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)&peeraddr;
        inet_ntop(AF_INET6, &a->sin6_addr, ipbuf, sizeof(ipbuf));
        portn = ntohs(a->sin6_port);
    }
    pm_add_or_update(&PM, remote_peerid, ipbuf, portn);

    char pidhex[41]; for (int i=0;i<20;i++) sprintf(pidhex+2*i, "%02x", remote_peerid[i]); pidhex[40]=0;
    fprintf(stderr, "[client] handshake success to %s:%u peerid=%s\n", ipbuf, portn, pidhex);

    send_interested(s); // Send interested
    // No sleep here. Immediately proceed to request piece.

    /* For testing piece exchange: if storage indicates piece 0 not present, request block 0 */
    if (STORAGE.num_pieces > 0 && !storage_is_piece_complete(&STORAGE, 0)) {
        uint32_t want = storage_piece_size(&STORAGE, 0);
        if (want > 16384) want = 16384;
        fprintf(stderr, "[client] requesting piece 0 begin=0 len=%u\n", want);
	    send_request_msg(s, 0, 0, want);
	    fprintf(stderr, "[DEBUG] entering piece request loop\n");
        while (1) {
            uint32_t len_be2;
            ssize_t r = readn(s, &len_be2, 4);
            if (r != 4) break;
            uint32_t len2 = ntohl(len_be2);
            if (len2 == 0) { fprintf(stderr, "[client] keepalive\n"); continue; }
            unsigned char id2;
            if (readn(s, &id2, 1) != 1) break;
            if (id2 == 7) { /* piece */
                unsigned char hdr[8];
                if (readn(s, hdr, 8) != 8) break;
                uint32_t pidx = ntohl(*(uint32_t*)(hdr+0));
                uint32_t pbegin = ntohl(*(uint32_t*)(hdr+4));
                uint32_t blklen = len2 - 9;
                unsigned char *blk = malloc(blklen ? blklen : 1);
                if (!blk) { skip_payload(s, blklen); continue; }
                if (readn(s, blk, blklen) != (ssize_t)blklen) { free(blk); break; }
                fprintf(stderr, "[client] got PIECE idx=%u begin=%u len=%u\n", pidx, pbegin, blklen);
                /* write block into local storage and verify */
                int rc = handle_piece_msg(s, remote_peerid, pidx, pbegin, blk, blklen, &STORAGE);
                free(blk);
                if (rc == 0 && storage_is_piece_complete(&STORAGE, pidx)) {
                    /* send HAVE back to server */
                    send_have(s, pidx);
                    fprintf(stderr, "[client] sending HAVE %u\n", pidx);
                    // Check if all pieces downloaded - simple check for 1 piece
                    if (STORAGE.num_pieces == 1 && storage_is_piece_complete(&STORAGE, 0)) { // For multiple pieces, would iterate over have_bits
                        fprintf(stderr, "[client] all requested pieces downloaded\n");
                    }
                }
                break;
            } else {
                /* skip other messages for test */
                if (len2 > 1) skip_payload(s, len2 - 1);
            }
        }
    }
    // Now, after the piece exchange loop (or if it wasn't entered), send other messages.
    send_not_interested(s);
    sleep(1);
    send_choke(s);
    sleep(1);
    send_unchoke(s);
    sleep(1);
    send_keepalive(s);
        sleep(1);
    
            fprintf(stderr, "[client] connection closed\n");
    
            fflush(stderr); // ADD THIS
    
            close(s);
    
            return 0;
}

/* ---------------- utility: peer_id generator ---------------- */
static void gen_peer_id(unsigned char peerid[20], const char *prefix) {
    // prefix typically like "-HS0001-"
    size_t plen = prefix ? strlen(prefix) : 0;
    if (plen > 12) plen = 12;
    memset(peerid, 0, 20);
    if (plen) memcpy(peerid, prefix, plen);
    // fill rest with random
    for (int i = (int)plen; i < 20; ++i) {
        unsigned char r = (unsigned char)(rand() % 256);
        peerid[i] = r;
    }
}

/* ---------------- main CLI and orchestration ---------------- */

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage:\n"
        "  %s --mode server --port <port> --torrent <file> [--peer-id <idstring>]\n"
        "  %s --mode client --connect <host:port> --torrent <file> [--peer-id <idstring>]\n", prog, prog);
}
typedef struct {
    const char *connect;
    unsigned char info_hash[20];
    unsigned char peer_id[20];
} client_thread_arg_t;

static void *client_thread(void *arg) {
    client_thread_arg_t *a = arg;
    client_run(a->connect, a->info_hash, a->peer_id);
    free(a);
    return NULL;
}
int main(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *mode = NULL;
    const char *port = NULL;
    const char *connect = NULL;
    const char *torrent = NULL;
    const char *peeridstr = NULL;

    for (int i=1;i<argc;i++){
        if (strcmp(argv[i], "--mode")==0 && i+1<argc) mode = argv[++i];
        else if (strcmp(argv[i], "--port")==0 && i+1<argc) port = argv[++i];
        else if (strcmp(argv[i], "--connect")==0 && i+1<argc) connect = argv[++i];
        else if (strcmp(argv[i], "--torrent")==0 && i+1<argc) torrent = argv[++i];
        else if (strcmp(argv[i], "--peer-id")==0 && i+1<argc) peeridstr = argv[++i];
        else { fprintf(stderr, "Unknown arg %s\n", argv[i]); usage(argv[0]); return 1; }
    }

    if (!mode) { usage(argv[0]); return 1; }
    if (!torrent) { fprintf(stderr, "torrent file required\n"); return 1; }

    // read torrent into buffer
    FILE *f = fopen(torrent, "rb");
    if (!f) { perror("fopen torrent"); return 1; }
    struct stat st; fstat(fileno(f), &st);
    size_t flen = (size_t)st.st_size;
    unsigned char *buf = malloc(flen);
    if (!buf) { fclose(f); return 1; }
    if (fread(buf, 1, flen, f) != flen) { perror("fread"); free(buf); fclose(f); return 1; }
    fclose(f);

    // find info slice
    size_t istart=0, iend=0;
    if (find_info_slice(buf, flen, &istart, &iend) != 0) {
        fprintf(stderr, "Failed to locate info slice in torrent\n"); free(buf); return 1;
    }
    fprintf(stderr, "info slice located at [%zu..%zu) size=%zu\n", istart, iend, iend-istart);

    fprintf(stderr, "[DEBUG] Before storage_init_from_info\n");
    if (storage_init_from_info(&STORAGE, buf + istart, iend - istart, torrent) < 0) {
        fprintf(stderr, "[fatal] storage init failed\n");
        exit(1);
    }
    fprintf(stderr, "[DEBUG] After storage_init_from_info\n");

    fprintf(stderr, "[storage] init: num_pieces=%u piece_len=%u total=%llu\n", STORAGE.num_pieces, STORAGE.piece_len, (unsigned long long)STORAGE.total_length);

    // compute sha256 truncated to 20 bytes
    unsigned char info_hash[20];
    if (compute_info_hash_sha256_truncated(buf, istart, iend, info_hash) != 0) {
        fprintf(stderr, "compute_info_hash failed\n"); free(buf); return 1;
    }
    char ihhex[41]; for (int i=0;i<20;i++) sprintf(ihhex+2*i, "%02x", info_hash[i]); ihhex[40]=0;
    fprintf(stderr, "info_hash (sha256 truncated 20 bytes) = %s\n", ihhex);

    // construct server/client peer_id
    unsigned char my_peerid[20];
    if (peeridstr) {
        // copy upto 20 bytes (pad with zeros if shorter)
        memset(my_peerid, 0, 20);
        size_t L = strlen(peeridstr); if (L>20) L=20;
        memcpy(my_peerid, peeridstr, L);
    } else {
        srand((unsigned)time(NULL) ^ (unsigned) getpid());
        gen_peer_id(my_peerid, "-HS0001-"); // default prefix
    }
    char pidhex[41]; for (int i=0;i<20;i++) sprintf(pidhex+2*i, "%02x", my_peerid[i]); pidhex[40]=0;
    fprintf(stderr, "local peer_id hex = %s\n", pidhex);

    // init peer manager
    pm_init(&PM);

    if (strcmp(mode, "server") == 0) {
        if (!port) { fprintf(stderr, "--port required for server\n"); free(buf); return 1; }
        // run server (blocking)
        server_run(port, info_hash, my_peerid);
    } else if (strcmp(mode, "client") == 0) {
        if (!connect) { fprintf(stderr, "--connect required for client\n"); free(buf); return 1; }
        // client: we can run multiple concurrent clients to test multiple handshakes
        // For demo, launch 3 concurrent handshakes
        const int N = 3;
        pthread_t thr[N];
        for (int i=0;i<N;i++)
        {
            client_thread_arg_t *a = malloc(sizeof(*a));
            a->connect = connect;
            memcpy(a->info_hash, info_hash, 20);
            gen_peer_id(a->peer_id, "-CL0001-");

            pthread_create(&thr[i], NULL, client_thread, a);
            pthread_detach(thr[i]);
        }
        sleep(4);
    } else {
        fprintf(stderr, "unknown mode\n");
        free(buf);
        return 1;
    }

    free(buf);
    return 0;
}