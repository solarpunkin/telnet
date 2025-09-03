#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <netdb.h>
#include "checksum.h"
#define OPENSSL_SUPPRESS_DEPRECATED

#define MAGIC "FSND"
#define BACKLOG 10
#define CHUNK 65536

static uint64_t ntohll_u64(uint64_t v) {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)ntohl(v & 0xFFFFFFFFULL) << 32) | ntohl((uint32_t)(v >> 32));
#else
    return v;
#endif
}

static ssize_t readn(int fd, void *buf, size_t n) {
    char *p = (char *)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t r = recv(fd, p, left, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return (ssize_t)(n - left); /* EOF */
        p += r; left -= (size_t)r;
    }
    return (ssize_t)n;
}

static int mkdir_p(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return S_ISDIR(st.st_mode) ? 0 : -1;
    return mkdir(path, 0755);
}

static int listen_tcp(const char *bind_addr, const char *port) {
    struct addrinfo hints, *res = NULL, *it = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family   = AF_UNSPEC;
    hints.ai_flags    = AI_PASSIVE;

    int rc = getaddrinfo(bind_addr, port, &hints, &res);
    if (rc != 0) { fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc)); return -1; }

    int srv = -1;
    for (it = res; it; it = it->ai_next) {
        srv = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (srv < 0) continue;
        int yes = 1;
        setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (bind(srv, it->ai_addr, it->ai_addrlen) == 0 && listen(srv, BACKLOG) == 0) break;
        close(srv); srv = -1;
    }
    freeaddrinfo(res);
    return srv;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <bind-addr> <port> <output-dir>\n", argv[0]);
        return 1;
    }
    const char *bind_addr = argv[1];
    const char *port      = argv[2];
    const char *outdir    = argv[3];

    if (mkdir_p(outdir) != 0) { perror("mkdir"); /* may exist, ignore */ }

    int srv = listen_tcp(bind_addr, port);
    if (srv < 0) { perror("listen"); return 1; }
    printf("Listening on %s:%s ...\n", bind_addr, port);

    for (;;) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof(ss);
        int cli = accept(srv, (struct sockaddr *)&ss, &slen);
        if (cli < 0) { perror("accept"); continue; }

        /* header */
        unsigned char hdr[4 + 2 + 2 + 8 + 2];
        if (readn(cli, hdr, sizeof(hdr)) != (ssize_t)sizeof(hdr)) { perror("read header"); close(cli); continue; }
        if (memcmp(hdr, MAGIC, 4) != 0) { fprintf(stderr, "Bad magic\n"); close(cli); continue; }

        uint16_t ver, flags, nlen;
        uint64_t size_n;
        memcpy(&ver,   hdr + 4, 2);
        memcpy(&flags, hdr + 6, 2);
        memcpy(&size_n,hdr + 8, 8);
        memcpy(&nlen,  hdr + 16, 2);

        ver   = ntohs(ver);
        flags = ntohs(flags);
        (void)flags;
        uint64_t fsize = ntohll_u64(size_n);
        uint16_t name_len = ntohs(nlen);

        if (ver != 1 || name_len == 0 || name_len > 4096) { fprintf(stderr, "Bad header\n"); close(cli); continue; }

        char *fname = malloc(name_len + 1);
        if (!fname) { perror("malloc"); close(cli); continue; }
        if (readn(cli, fname, name_len) != name_len) { perror("read name"); free(fname); close(cli); continue; }
        fname[name_len] = '\0';

        /* open out file */
        char path[4096];
        snprintf(path, sizeof(path), "%s/%s", outdir, fname);
        free(fname);

        FILE *fp = fopen(path, "wb");
        if (!fp) { perror("fopen out"); close(cli); continue; }

        crc32_ctx ccrc;  crc32_init(&ccrc);
        sha1_ctx  csha;  sha1_init(&csha);

        unsigned char *buf = malloc(CHUNK);
        if (!buf) { perror("malloc"); fclose(fp); close(cli); continue; }

        uint64_t left = fsize;
        while (left > 0) {
            size_t want = (left > CHUNK) ? CHUNK : (size_t)left;
            ssize_t r = readn(cli, buf, want);
            if (r <= 0) { perror("read data"); break; }
            if (fwrite(buf, 1, (size_t)r, fp) != (size_t)r) { perror("fwrite"); break; }
            crc32_update(&ccrc, buf, (size_t)r);
            sha1_update(&csha, buf, (size_t)r);
            left -= (size_t)r;
        }
        free(buf);
        fflush(fp); fclose(fp);

        if (left != 0) { fprintf(stderr, "Connection ended early\n"); close(cli); continue; }

        /* read checksums */
        uint32_t crc32_n;
        unsigned char sha1_recv[20];
        if (readn(cli, &crc32_n, sizeof(crc32_n)) != sizeof(crc32_n)) { perror("read crc32"); close(cli); continue; }
        if (readn(cli, sha1_recv, sizeof(sha1_recv)) != sizeof(sha1_recv)) { perror("read sha1"); close(cli); continue; }
        close(cli);

        uint32_t crc32_calc = crc32_final(&ccrc);
        unsigned char sha1_calc[20];
        sha1_final(&csha, sha1_calc);

        uint32_t crc32_rx = ntohl(crc32_n);

        int ok_crc = (crc32_calc == crc32_rx);
        int ok_sha = (memcmp(sha1_calc, sha1_recv, 20) == 0);

        printf("Received '%s' (%llu bytes) -> %s\n",
               path, (unsigned long long)fsize, (ok_crc && ok_sha) ? "OK" : "BAD");

        printf("CRC32 local=0x%08X remote=0x%08X [%s]\n",
               crc32_calc, crc32_rx, ok_crc ? "match" : "MISMATCH");

        printf("SHA1  local=");
        for (int i = 0; i < 20; i++) printf("%02x", sha1_calc[i]);
        printf("  remote=");
        for (int i = 0; i < 20; i++) printf("%02x", sha1_recv[i]);
        printf(" [%s]\n", ok_sha ? "match" : "MISMATCH");
    }
}
