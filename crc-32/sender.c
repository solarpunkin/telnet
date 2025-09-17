/* 
-- Reads a files and computes crc32 over its contents
-- sends file size, file data, and the crc32 digest to the receiver. 
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "crc32.h"

#define PORT 8080
#define BUF_SIZE 4096
static ssize_t writen(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t left = n;
    while (left) {
        ssize_t w = send(fd, p, left, 0);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        left -= w;
    }
    return (ssize_t)n;
}
int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    FILE *fp;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, argv[1], &serv_addr.sin_addr) <= 0) {
        perror("Invalid address/Address not supported");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }

    fp = fopen(argv[2], "rb");
    if (!fp) {
        perror("File open error");
        exit(EXIT_FAILURE);
    }

    // Get file size
    fseek(fp, 0, SEEK_END);
    uint64_t filesize = ftell(fp);
    rewind(fp);

    // Send file size first
    writen(sock, &filesize, sizeof(filesize));

    // Compute CRC32 before sending file
    size_t n;
    uint32_t crc = 0xFFFFFFFFu;
    unsigned char buffer[BUF_SIZE];

    while ((n = fread(buffer, 1, sizeof(buffer), fp)) > 0) {
        if (writen(sock, buffer, n) != (ssize_t)n) {
            perror("Send failed");
            fclose(fp);
            close(sock);
            exit(EXIT_FAILURE);
        }
        crc = xcrc32(buffer, (int)n, crc);
    }
    fclose(fp);

    // Send CRC32
    uint32_t new_crc = htonl(crc);
    writen(sock, &new_crc, sizeof(new_crc));

    printf("File sent successfully with CRC32: %08X\n", crc);
    
    close(sock);
    return 0;
}
