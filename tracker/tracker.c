// tracker.c
// Simple UDP-based tracker + HTTP REST peer listing (bencoded responses).
// Not full BEP15 UDP tracker; 
//
// Build: cc -O2 -std=c11 tracker.c -o tracker -lpthread
//
// Usage: ./tracker --udp-port 9000 --http-port 8080

#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include "encoder.h"

#define DEFAULT_UDP_PORT 9000
#define DEFAULT_HTTP_PORT 8080
#define PEER_TIMEOUT_SECONDS 60 * 5  // 5 minutes
#define MAX_INFOHASH 20

// Peer record
typedef struct peer {
    unsigned char info_hash[20];
    unsigned char peer_id[20];
    char ipstr[INET6_ADDRSTRLEN];
    uint16_t port;
    bool seeder;
    time_t last_seen;
    struct peer *next;
} peer_t;

// Bucket per infohash (simple chained list of peers)
typedef struct info_bucket {
    unsigned char info_hash[20];
    peer_t *peers;
    struct info_bucket *next;
} info_bucket_t;

// Tracker state
typedef struct tracker_state {
    info_bucket_t *buckets;
    pthread_mutex_t lock;
    int udp_port;
    int http_port;
    int udp_sock;
    int http_sock;
    bool running;
} tracker_state_t;

static tracker_state_t T;

// ---- utilities ----
static void hex_encode(const unsigned char *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        unsigned char v = in[i];
        out[2*i]   = hex[v >> 4];
        out[2*i+1] = hex[v & 0xF];
    }
    out[2*len] = '\0';
}

static int hex_char_to_int(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

static int hex_decode(const char *hex, unsigned char *out, size_t out_len)
{
    size_t hlen = strlen(hex);
    if (hlen != out_len * 2) return -1;
    for (size_t i = 0; i < out_len; ++i) {
        int hi = hex[i*2];
        int lo = hex[i*2+1];
        int a = hex_char_to_int(hi);
        int b = hex_char_to_int(lo);
        if (a < 0 || b < 0) return -1;
        out[i] = (unsigned char)((a << 4) | b);
    }
    return 0;
}

// find bucket by infohash; returns with lock held (caller must hold T.lock)
static info_bucket_t *find_bucket_nolock(const unsigned char info_hash[20]) {
    info_bucket_t *it = T.buckets;
    while (it) {
        if (memcmp(it->info_hash, info_hash, 20) == 0) return it;
        it = it->next;
    }
    return NULL;
}

// create new bucket (caller must hold lock)
static info_bucket_t *create_bucket_nolock(const unsigned char info_hash[20]) {
    info_bucket_t *b = calloc(1, sizeof(info_bucket_t));
    if (!b) return NULL;
    memcpy(b->info_hash, info_hash, 20);
    b->peers = NULL;
    b->next = T.buckets;
    T.buckets = b;
    return b;
}

// register or update peer
static void register_peer(const unsigned char info_hash[20],
                          const unsigned char peer_id[20],
                          const char *ipstr, uint16_t port,
                          bool seeder)
{
    pthread_mutex_lock(&T.lock);
    info_bucket_t *b = find_bucket_nolock(info_hash);
    if (!b) b = create_bucket_nolock(info_hash);
    if (!b) { pthread_mutex_unlock(&T.lock); return; }

    // search peer by ip/port (and peer_id if provided)
    peer_t *p = b->peers;
    while (p) {
        if (p->port == port && strcmp(p->ipstr, ipstr) == 0 && memcmp(p->peer_id, peer_id, 20) == 0) break;
        p = p->next;
    }
    if (!p) {
        p = calloc(1, sizeof(peer_t));
        if (!p) { pthread_mutex_unlock(&T.lock); return; }
        memcpy(p->info_hash, info_hash, 20);
        memcpy(p->peer_id, peer_id, 20);
        strncpy(p->ipstr, ipstr, sizeof(p->ipstr)-1);
        p->port = port;
        p->seeder = seeder;
        p->last_seen = time(NULL);
        p->next = b->peers;
        b->peers = p;
    } else {
        p->last_seen = time(NULL);
        p->seeder = seeder;
    }
    pthread_mutex_unlock(&T.lock);
}

// build bencoded response in buffer (caller must free the returned buffer)
// bencoded dict: d8:intervali<interval>e5:peersl (list of dicts) e
// Each peer dict: d2:ip<ipstr>4:porti<port>e7:peer id20:<20bytes>e
// returns malloc'd buffer and sets out_len
static unsigned char *build_peers_bencode(const unsigned char info_hash[20], size_t *out_len) {
    // gather snapshot under lock
    pthread_mutex_lock(&T.lock);
    info_bucket_t *b = find_bucket_nolock(info_hash);
    if (!b) {
        // return minimal dict with zero peers
        const char *minimal = "d8:intervali1800e5:peersle";
        *out_len = strlen(minimal);
        unsigned char *buf = malloc(*out_len);
        memcpy(buf, minimal, *out_len);
        pthread_mutex_unlock(&T.lock);
        return buf;
    }
    // create writer
    benc_w *w = bencw_new(1024);
    if (!w) { pthread_mutex_unlock(&T.lock); return NULL; }

    // build dictionary: d 8:intervali1800e 5:peersl ... e e
    if (bencw_start_dict(w) != 0) goto err;
    // key "interval" (8:interval)
    if (bencw_put_str(w, "interval", 8) != 0) goto err;
    if (bencw_put_int(w, 1800) != 0) goto err;

    // key "peers"
    if (bencw_put_str(w, "peers", 5) != 0) goto err;
    if (bencw_start_list(w) != 0) goto err;

    // iterate peers
    peer_t *p = b->peers;
    while (p) {
        if (bencw_start_dict(w) != 0) goto err;

        // 2:ip<ipstr>
        size_t iplen = strlen(p->ipstr);
        if (bencw_put_str(w, "ip", 2) != 0) goto err;
        if (bencw_put_str(w, p->ipstr, iplen) != 0) goto err;

        // 4:port i<port>e
        if (bencw_put_str(w, "port", 4) != 0) goto err;
        if (bencw_put_int(w, (long long)p->port) != 0) goto err;

        // 7:peer id20:<20 bytes>
        if (bencw_put_str(w, "peer id", 7) != 0) goto err;
        // append raw 20 bytes (not string-escaped)
        if (bencw_put_str(w, (const char *)p->peer_id, 20) != 0) goto err;

        if (bencw_end_dict(w) != 0) goto err;
        p = p->next;
    }

    if (bencw_end_list(w) != 0) goto err;
    if (bencw_end_dict(w) != 0) goto err;

    // done
    size_t len = bencw_len(w);
    unsigned char *out = malloc(len);
    if (!out) goto err;
    memcpy(out, bencw_buf(w), len);
    *out_len = len;
    bencw_free(w);
    pthread_mutex_unlock(&T.lock);
    return out;

err:
    bencw_free(w);
    pthread_mutex_unlock(&T.lock);
    return NULL;
}


// HTTP simple utility to send response
static int sendall(int fd, const void *buf, size_t len) {
    const unsigned char *p = buf;
    size_t left = len;
    while (left) {
        ssize_t s = send(fd, p, left, 0);
        if (s < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += s; left -= s;
    }
    return 0;
}

// naive query parser to extract info_hash hex param
static int extract_infohash_from_query(const char *q, unsigned char out20[20]) {
    // q looks like "info_hash=abcdef...&other=..."
    // simple search "info_hash="
    const char *p = strstr(q, "info_hash=");
    if (!p) return -1;
    p += strlen("info_hash=");
    // read up to 40 hex chars
    char hex[41]; int i = 0;
    while (*p && *p != '&' && i < 40) {
        hex[i++] = *p++;
    }
    hex[i] = 0;
    if (i != 40) return -1;
    if (hex_decode(hex, out20, 20) != 0) return -1;
    return 0;
}

// very small HTTP request handler (single-threaded per accept)
static void handle_http_client(int cli_fd) {
    // read request (very small)
    char buf[4096];
    ssize_t r = recv(cli_fd, buf, sizeof(buf)-1, 0);
    if (r <= 0) { close(cli_fd); return; }
    buf[r] = 0;
    // parse first line "GET /peers?info_hash=... HTTP/1.1"
    char method[8], path[512];
    if (sscanf(buf, "%7s %511s", method, path) != 2) { close(cli_fd); return; }
    if (strcmp(method, "GET") != 0) {
        const char *resp = "HTTP/1.1 405 Method Not Allowed\r\n\r\n";
        sendall(cli_fd, resp, strlen(resp));
        close(cli_fd);
        return;
    }

    // path may be "/peers?info_hash=..."
    char *q = strchr(path, '?');
    unsigned char infoh[20];
    int ok = 0;
    if (q && strncmp(path, "/peers", 6) == 0) {
        ok = (extract_infohash_from_query(q+1, infoh) == 0);
    }
    if (!ok) {
        const char *resp = "HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n\r\nBad Request";
        sendall(cli_fd, resp, strlen(resp));
        close(cli_fd);
        return;
    }

    // build bencoded peers response
    size_t out_len = 0;
    unsigned char *benc = build_peers_bencode(infoh, &out_len);
    if (!benc) {
        const char *resp = "HTTP/1.1 500 Internal Server Error\r\n\r\nServer Error";
        sendall(cli_fd, resp, strlen(resp));
        close(cli_fd);
        return;
    }

    // HTTP response
    char hdr[256];
    int hdrlen = snprintf(hdr, sizeof(hdr),
                          "HTTP/1.1 200 OK\r\n"
                          "Content-Type: application/x-bittorrent\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n"
                          "\r\n", out_len);
    sendall(cli_fd, hdr, hdrlen);
    sendall(cli_fd, benc, out_len);
    free(benc);
    close(cli_fd);
}

// UDP announce handling thread
static void *udp_server_thread(void *arg) {
    (void)arg;
    char addrbuf[INET6_ADDRSTRLEN];

    struct sockaddr_storage cliaddr;
    socklen_t cliaddr_len = sizeof(cliaddr);
    unsigned char pkt[1 + 20 + 20 + 2 + 1]; // type + infohash + peerid + port + flags
    while (T.running) {
        ssize_t n = recvfrom(T.udp_sock, pkt, sizeof(pkt), 0,
                             (struct sockaddr *)&cliaddr, &cliaddr_len);
        if (n <= 0) { if (errno == EINTR) continue; break; }
        if (n < 1 + 20 + 20 + 2 + 1) {
            // ignore too small packets
            continue;
        }
        unsigned char type = pkt[0];
        if (type != 0x01) continue; // only ANNOUNCE in our simplified protocol
        unsigned char infoh[20];
        unsigned char peerid[20];
        memcpy(infoh, pkt+1, 20);
        memcpy(peerid, pkt+1+20, 20);
        uint16_t port;
        memcpy(&port, pkt+1+20+20, 2);
        port = ntohs(port);
        unsigned char flags = pkt[1+20+20+2];
        bool seeder = (flags & 0x1);

        // determine IP from cliaddr
        if (cliaddr.ss_family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&cliaddr;
            inet_ntop(AF_INET, &s4->sin_addr, addrbuf, sizeof(addrbuf));
        } else {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)&cliaddr;
            inet_ntop(AF_INET6, &s6->sin6_addr, addrbuf, sizeof(addrbuf));
        }

        register_peer(infoh, peerid, addrbuf, port, seeder);

        // respond with an ack (type=0x02, status=0)
        unsigned char resp[2];
        resp[0] = 0x02; resp[1] = 0x00;
        sendto(T.udp_sock, resp, sizeof(resp), 0, (struct sockaddr *)&cliaddr, cliaddr_len);
    }
    return NULL;
}

// HTTP server thread (simple accept loop)
static void *http_server_thread(void *arg) {
    (void)arg;
    while (T.running) {
        struct sockaddr_storage cli; socklen_t clilen = sizeof(cli);
        int cli_fd = accept(T.http_sock, (struct sockaddr *)&cli, &clilen);
        if (cli_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }
        // handle request in detached thread or inline; do simple thread to avoid blocking
        pid_t pid = fork();
        if (pid == 0) {
            // child
            close(T.http_sock);
            handle_http_client(cli_fd);
            exit(0);
        } else if (pid > 0) {
            // parent
            close(cli_fd);
            // reap children occasionally with SIGCHLD ignored or waitpid in cleaner; simple approach: set SIGCHLD to SIG_IGN
        } else {
            // fork failed -> handle inline
            handle_http_client(cli_fd);
        }
    }
    return NULL;
}

// peer expiry cleaner
static void *cleaner_thread(void *arg) {
    (void)arg;
    while (T.running) {
        sleep(30);
        time_t now = time(NULL);
        pthread_mutex_lock(&T.lock);
        info_bucket_t *b = T.buckets;
        while (b) {
            peer_t **pp = &b->peers;
            while (*pp) {
                peer_t *p = *pp;
                if (now - p->last_seen > PEER_TIMEOUT_SECONDS) {
                    *pp = p->next;
                    free(p);
                } else pp = &p->next;
            }
            b = b->next;
        }
        pthread_mutex_unlock(&T.lock);
    }
    return NULL;
}

// graceful shutdown
static void handle_sigint(int sig) {
    (void)sig;
    fprintf(stderr, "shutting down tracker...\n");
    T.running = false;
    // close sockets to break accept/recv loops
    if (T.udp_sock > 0) close(T.udp_sock);
    if (T.http_sock > 0) close(T.http_sock);
}

int main(int argc, char **argv) {
    int udp_port = DEFAULT_UDP_PORT;
    int http_port = DEFAULT_HTTP_PORT;

    // arg parsing
    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--udp-port") == 0 && i+1 < argc) udp_port = atoi(argv[++i]);
        else if (strcmp(argv[i], "--http-port") == 0 && i+1 < argc) http_port = atoi(argv[++i]);
        else { fprintf(stderr, "unknown arg %s\n", argv[i]); return 1;}
    }

    memset(&T, 0, sizeof(T));
    pthread_mutex_init(&T.lock, NULL);
    T.running = true;
    T.udp_port = udp_port;
    T.http_port = http_port;

    signal(SIGINT, handle_sigint);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGCHLD, SIG_IGN); // let children be reaped automatically

    // UDP socket
    T.udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (T.udp_sock < 0) { perror("socket udp"); return 1; }
    struct sockaddr_in ua = {0};
    ua.sin_family = AF_INET;
    ua.sin_addr.s_addr = INADDR_ANY;
    ua.sin_port = htons((uint16_t)udp_port);
    if (bind(T.udp_sock, (struct sockaddr *)&ua, sizeof(ua)) != 0) { perror("bind udp"); close(T.udp_sock); return 1; }

    // HTTP socket
    T.http_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (T.http_sock < 0) { perror("socket http"); close(T.udp_sock); return 1; }
    int yes = 1; setsockopt(T.http_sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    struct sockaddr_in ha = {0};
    ha.sin_family = AF_INET;
    ha.sin_addr.s_addr = INADDR_ANY;
    ha.sin_port = htons((uint16_t)http_port);
    if (bind(T.http_sock, (struct sockaddr *)&ha, sizeof(ha)) != 0) { perror("bind http"); close(T.udp_sock); close(T.http_sock); return 1; }
    if (listen(T.http_sock, 16) != 0) { perror("listen http"); close(T.udp_sock); close(T.http_sock); return 1; }

    // spawn threads
    pthread_t udp_thr, http_thr, clean_thr;
    pthread_create(&udp_thr, NULL, udp_server_thread, NULL);
    pthread_create(&http_thr, NULL, http_server_thread, NULL);
    pthread_create(&clean_thr, NULL, cleaner_thread, NULL);

    fprintf(stderr, "tracker running: udp=%d http=%d\n", udp_port, http_port);

    // wait until shutdown
    pthread_join(udp_thr, NULL);
    pthread_join(http_thr, NULL);
    pthread_join(clean_thr, NULL);

    // cleanup buckets
    pthread_mutex_lock(&T.lock);
    info_bucket_t *b = T.buckets;
    while (b) {
        peer_t *p = b->peers;
        while (p) { peer_t *nx = p->next; free(p); p = nx; }
        info_bucket_t *bn = b->next;
        free(b);
        b = bn;
    }
    pthread_mutex_unlock(&T.lock);
    pthread_mutex_destroy(&T.lock);
    return 0;
}
