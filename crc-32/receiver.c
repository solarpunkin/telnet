/*
-- Accepts file and computes its own crc32
-- compares against sender's crc32
-- reports success/failure
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "crc32.h"

#define PORT 8080
#define BUF_SIZE 1024

int main() {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int addrlen = sizeof(address);
    char buffer[BUF_SIZE];
    size_t n;
    long filesize, received = 0;
    uint32_t recv_crc, calc_crc = 0;
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
    read(new_socket, &filesize, sizeof(filesize));
    printf("Incoming file of size %ld bytes\n", filesize);

    fp = fopen("received_file", "wb");
    if (!fp) {
        perror("File create error");
        exit(EXIT_FAILURE);
    }

    while (received < filesize) {
        n = read(new_socket, buffer, BUF_SIZE);
        if (n <= 0) break;
        fwrite(buffer, 1, n, fp);
        calc_crc = xcrc32((unsigned char *)buffer, n, calc_crc);
        received += n;
    }
    fclose(fp);

    // Receive sender’s CRC32
    read(new_socket, &recv_crc, sizeof(recv_crc));

    printf("Sender CRC32: %08X\n", recv_crc);
    printf("Calc   CRC32: %08X\n", calc_crc);

    if (recv_crc == calc_crc)
        printf("CRC32 matches!\n");
    else
        printf("CRC32 mismatch!\n");

    close(new_socket);
    close(server_fd);
    return 0;
}
