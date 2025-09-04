/* 
-- Reads a files and computes crc32 over its contents
-- sends file size, file data, and the crc32 digest to the receiver. 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "crc32.h"

#define PORT 8080
#define BUF_SIZE 1024

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server_ip> <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUF_SIZE];
    FILE *fp;
    size_t n;
    uint32_t crc = 0;

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
    long filesize = ftell(fp);
    rewind(fp);

    // Send file size first
    write(sock, &filesize, sizeof(filesize));

    // Compute CRC32 before sending file
    while ((n = fread(buffer, 1, BUF_SIZE, fp)) > 0) {
        write(sock, buffer, n);
        crc = xcrc32((unsigned char *)buffer, n, crc);
    }
    fclose(fp);

    // Send CRC32
    write(sock, &crc, sizeof(crc));

    printf("File sent successfully with CRC32: %08X\n", crc);

    close(sock);
    return 0;
}
