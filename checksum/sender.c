#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
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
#define OPENSSL_SUPPRESS_DEPRECATED


#include "checksum.h"

#define MAGIC "FSND"
#define VERSION 1
#define CHUNK 65536

static uint64_t htonll_u64(uint64_t v) {
    #if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return ((uint64_t)htonl(v & 0xFFFFFFFFULL) << 32) | htonl((uint32_t)(v >> 32));
    #else
    return v;
    #endif
}
static int writen(int fd, const void *buf, size_t n) {
    const char *p = (const char *)buf;
    size_t left = n;
    while (left > 0) {
        ssize_t w = send(fd, p, left, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) continue;
        p += w;
        left -= (size_t)w;
    }
    return 0;
}

static int connect_tcp(const char *host, const char *port) {
    struct addrinfo hints, *res = NULL, *it = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    int rc = getaddrinfo(host, port, &hints, &res);
    if (rc != 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rc));
        return -1;
    }
    int fd = -1;
    for (it = res; it; it = it->ai_next) {
        fd = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
        if (fd < 0) continue;
        if (connect(fd, it->ai_addr, it->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    return fd;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server-host> <port> <file>\n", argv[0]);
        return 1;
    }
    const char *host = argv[1];
    const char *port = argv[2];
    const char *path = argv[3];

    int fd = connect_tcp(host, port);
    if (fd < 0) {
        perror("connect");
        return 1;
    }

    /*open file*/
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen"); 
        close (fd);
        return 1;
    }

    /* stat for size + filename */
    struct stat st;
    if (stat(path, &st) != 0) {
        perror("stat");
        fclose(fp);
        close(fd);
        return 1;
    }

    uint64_t fsize = (uint64_t)st.st_size;
    const char *slash = strrchr(path, '/');
    const char *fname = slash ? slash + 1 : path;
    uint16_t name_len = (uint16_t)strlen(fname);

    /* header */
    unsigned char hdr[4 + 2 + 2 + 8 + 2];
    memcpy(hdr, MAGIC, 4);
    uint16_t ver_n = htons(VERSION);
    uint16_t flags_n = htons(0);
    uint64_t size_n = htonll_u64(fsize);
    uint16_t nlen_n = htons(name_len);

    memcpy(hdr + 4, &ver_n, 2);
    memcpy(hdr + 6, &flags_n, 2);
    memcpy(hdr + 8, &size_n, 8);
    memcpy(hdr + 16, &nlen_n, 2);

    if (writen(fd, hdr, sizeof(hdr)) < 0) {
        perror("send header");
        return 1;
    }
    if (writen(fd, fname, name_len) < 0) {
        perror("send name");
        return 1;
    }

    /* checksums while sending */
    crc32_ctx ccrc; crc32_init(&ccrc);
    sha1_ctx csha; sha1_init(&csha);

    unsigned char *buf = malloc(CHUNK);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    size_t nread;
    while ((nread = fread(buf, 1, CHUNK, fp)) > 0) {
        if (writen(fd, buf, nread) < 0) {
            perror("send data");
            free(buf);
            return 1;
        }
        crc32_update(&ccrc, buf, nread);
        sha1_update(&csha, buf, nread);
    }
    if (ferror(fp)) {
        perror("fread");
        free(buf);
        return 1;
    }
    free(buf);
    uint32_t crc32 = crc32_final(&ccrc);
    unsigned char sha1[20];
    sha1_final(&csha, sha1);

    uint32_t crc32_n = htonl(crc32);
    if (writen(fd, &crc32_n, sizeof(crc32_n)) < 0) {
        perror("send crc32");
        return 1;
    }
    if (writen(fd, sha1, sizeof(sha1)) < 0) {
        perror("send sha1");
        return 1;
    }

    fclose(fp);
    close(fd);

    printf("Sent %s (%llu bytes)\nCRC32=0x%08X\nSHA1=", fname, (unsigned long long)fsize, crc32);
    for (int i = 0; i < 20; i++) printf("%02x", sha1[i]);
    printf("\n");
    return 0;

}