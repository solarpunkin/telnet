// handshake.c
// BitTorrent-style TCP handshake implementation (server + client) using SHA-256-on-info
// and truncating to 20 bytes for the handshake info_hash.
// Reuses existing bencode parser to locate the exact bencoded "info" slice.
// Build: cc -O2 -std=c11 handshake.c bencode.c -o handshake -lcrypto -lpthread
// Build command works: cc -O2 -std=c11 handshake.c bencode.c -o handshake 
// -I/opt/homebrew/opt/openssl@3/include -L/opt/homebrew/opt/openssl@3/lib -lssl -lcrypto -lpthread
//
// Usage:
//   Server: ./handshake --mode server --port 6881 --torrent my.torrent --peer-id "-HS0001-1234567890"
//   Client: ./handshake --mode client --connect 127.0.0.1:6881 --torrent my.torrent
//
// The server accepts TCP connections and performs the standard peer handshake:
//  <pstrlen><pstr><reserved><info_hash><peer_id>
// Both sides send handshake; each validates info_hash matches the local torrent's info_hash.
// After successful handshake, peers are registered in an in-memory peer manager.
//
// We compute SHA-256(info_bencoded) and truncate to 20 bytes

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bencode.h"  
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
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, buf + start, end - start);
    SHA256_Final(digest, &ctx);
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

/* ---------------- server code ---------------- */

typedef struct {
    int client_fd;
    struct sockaddr_storage cliaddr;
    socklen_t cliaddr_len;
    unsigned char info_hash[20];
    unsigned char server_peer_id[20];
} server_conn_ctx_t;

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

    // log success
    char pidhex[41]; for (int i=0;i<20;i++) sprintf(pidhex+2*i, "%02x", remote_peerid[i]); pidhex[40]=0;
    fprintf(stderr, "[server] handshake success with %s:%u peerid=%s\n", ipbuf, port, pidhex);

    // keep the connection open for future messages (not implemented here).
    // For demo, sleep a little and close.
    sleep(1);

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

    // keep open a short while
    sleep(1);
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
        sleep(3);

        // typedef struct { const char *cp; unsigned char ih[20]; unsigned char pid[20]; } cctx_t;
        // cctx_t *cctxs[N];
        // for (int i=0;i<N;i++){
        //     cctxs[i] = malloc(sizeof(cctx_t));
        //     cctxs[i]->cp = connect;
        //     memcpy(cctxs[i]->ih, info_hash, 20);
        //     // create different peer ids for each client
        //     unsigned char pid[20];
        //     gen_peer_id(pid, "-CL0001-");
        //     memcpy(cctxs[i]->pid, pid, 20);
        //     pthread_create(&thr[i], NULL, (void*(*)(void*)) (void*) (^(void *arg)->void* { // workaround not allowed: we will use a wrapper below
        //         return NULL;
        //     }), NULL);
        // }
        // // The above hack is messy in C - instead we will spawn client runs sequentially in threads with a simple wrapper.
        // // Clean approach: create a small helper function.
        // for (int i=0;i<N;i++) pthread_detach(pthread_create_wrapper((void*)connect, info_hash, cctxs[i]->pid)); 
        // // But we can't do that - C doesn't support easy lambda here.
        // // Simpler: run clients sequentially (less concurrency) and show multiple handshakes.
        // for (int i=0;i<3;i++) {
        //     unsigned char pid[20];
        //     gen_peer_id(pid, "-CL0001-");
        //     client_run(connect, info_hash, pid);
        // }
    } else {
        fprintf(stderr, "unknown mode\n");
        free(buf);
        return 1;
    }

    free(buf);
    return 0;
}
