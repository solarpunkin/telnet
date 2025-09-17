/*
-- Accepts file and computes its own crc32
-- compares against sender's crc32
-- reports success/failure
*/

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>
#include "crc32.h"

#define CHUNK 4096
#define BACKLOG 8

#define PORT 8080
#define BUF_SIZE 1024

static ssize_t readn(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t left = n;
    while (left) {
        ssize_t r = recv(fd, p, left, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) return (ssize_t)(n - left); // EOF
        p += r;
        left -= r;
    }
    return (ssize_t)n;
}

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    uint64_t filesize;
    uint32_t recv_crc;
    FILE *fp;

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d...\n", PORT);

    if ((new_socket = accept(server_fd, (struct sockaddr *)&address,
                             (socklen_t *)&addrlen)) < 0) {
        perror("accept");
        exit(EXIT_FAILURE);
    }

    // Receive file size
    readn(new_socket, &filesize, sizeof(filesize));
    printf("Incoming file of size %llu bytes\n", filesize);

    fp = fopen("received_file", "wb");
    if (!fp) {
        perror("File create error");
        exit(EXIT_FAILURE);
    }

    uint32_t calc_crc = 0xFFFFFFFFu;
    uint64_t left = filesize;
    unsigned char buf[CHUNK];
    while (left) {
        size_t want = (left > CHUNK) ? CHUNK : (size_t)left;
        ssize_t r = readn(new_socket, buf, want);
        if (r <= 0) { perror("read data"); fclose(fp); close(new_socket); close(server_fd); exit(EXIT_FAILURE); }
        if (fwrite(buf, 1, (size_t)r, fp) != (size_t)r) { perror("fwrite"); fclose(fp); close(new_socket); close(server_fd); exit(EXIT_FAILURE); }
        calc_crc = xcrc32(buf, (int)r, calc_crc);
        left -= (size_t)r;
    }
    fflush(fp);
    fclose(fp);

    // Receive sender’s CRC32
    if (readn(new_socket, &recv_crc, sizeof(recv_crc)) != sizeof(recv_crc)) {
        perror("read crc");
        close(new_socket);
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    uint32_t recv_crc_net = ntohl(recv_crc);

    printf("Sender CRC32: %08X\n", recv_crc_net);
    printf("Calc   CRC32: %08X\n", calc_crc);

    if (recv_crc_net == calc_crc)
        printf("CRC32 matches!\n");
    else
        printf("CRC32 mismatch!\n");

    close(new_socket);
    close(server_fd);
    return 0;
}
