#define _POSIX_C_SOURCE 200809L
#include "peer_wire.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "storage.h"

/* send helpers */
int send_request_msg(int fd, uint32_t index, uint32_t begin, uint32_t length) {
    uint32_t payload_len = 1 + 4 + 4 + 4; // Length of ID + index + begin + length (13 bytes)
    uint32_t total_msg_len_be = htonl(payload_len); // B-endian for total payload length
    unsigned char buf[4 + payload_len]; // Total message size (4-byte length prefix + payload) = 17 bytes

    memcpy(buf, &total_msg_len_be, 4); 
    buf[4] = 6; 
    uint32_t be_index = htonl(index);
    uint32_t be_begin = htonl(begin);
    uint32_t be_len = htonl(length);

    memcpy(buf+5, &be_index, 4); 
    memcpy(buf+9, &be_begin, 4); 
    memcpy(buf+13, &be_len, 4); 

    ssize_t w = write(fd, buf, sizeof(buf)); // sizeof(buf) = 17
    return (w == (ssize_t)sizeof(buf)) ? 0 : -1;
}

int send_cancel_msg(int fd, uint32_t index, uint32_t begin, uint32_t length) {
    uint32_t payload_len = 1 + 4 + 4 + 4; // Length of ID + index + begin + length (13 bytes)
    uint32_t total_msg_len_be = htonl(payload_len); // B-endian for total payload length
    unsigned char buf[4 + payload_len]; // Total message size (4-byte length prefix + payload) = 17 bytes

    memcpy(buf, &total_msg_len_be, 4); 
    buf[4] = 8; 
    uint32_t be_index = htonl(index);
    uint32_t be_begin = htonl(begin);
    uint32_t be_len = htonl(length);

    memcpy(buf+5, &be_index, 4); 
    memcpy(buf+9, &be_begin, 4); 
    memcpy(buf+13, &be_len, 4); 

    ssize_t w = write(fd, buf, sizeof(buf)); // sizeof(buf) = 17
    return (w == (ssize_t)sizeof(buf)) ? 0 : -1;
}

/* send piece: build length, id=7, index(4), begin(4), block */
int send_piece_msg(int fd, uint32_t index, uint32_t begin, const void *block, uint32_t blocklen) {
    uint64_t totlen = 1 + 4 + 4 + blocklen;
    if (totlen > 0x7fffffff) return -1;
    uint32_t be_len = htonl((uint32_t)totlen);
    // write header
    if (write(fd, &be_len, 4) != 4) return -1;
    unsigned char id = 7;
    if (write(fd, &id, 1) != 1) return -1;
    uint32_t be_index = htonl(index);
    uint32_t be_begin = htonl(begin);
    if (write(fd, &be_index, 4) != 4) return -1;
    if (write(fd, &be_begin, 4) != 4) return -1;
    if (write(fd, block, blocklen) != (ssize_t)blocklen) return -1;
    return 0;
}

/* handle request: read requested block from storage and send piece */
int handle_request_msg(int peer_fd, const unsigned char *peerid, uint32_t index, uint32_t begin, uint32_t length, storage_t *storage) {
    (void)peerid;
    if (!storage) return -1;
    uint32_t psize = storage_piece_size(storage, index);
    if (begin + length > psize) {
        fprintf(stderr, "[peer_wire] request out of bounds index=%u begin=%u length=%u psize=%u\n", index, begin, length, psize);
        return -1;
    }
    unsigned char *buf = malloc(length);
    if (!buf) return -1;
    if (storage_read_block(storage, index, begin, buf, length) != 0) {
        fprintf(stderr, "[peer_wire] failed read_block\n");
        free(buf);
        return -1;
    }
    // send piece
    if (send_piece_msg(peer_fd, index, begin, buf, length) != 0) {
        fprintf(stderr, "[peer_wire] failed send_piece\n");
        free(buf);
        return -1;
    }
    fprintf(stderr, "[server] sending PIECE index=%u begin=%u len=%u\n", index, begin, length);
    free(buf);
    return 0;
}

/* handle incoming piece: write to disk via storage_write_block_and_check */
int handle_piece_msg(int peer_fd, const unsigned char *peerid, uint32_t index, uint32_t begin, const unsigned char *data, uint32_t datalen, storage_t *storage) {
    (void)peer_fd; (void)peerid;
    if (!storage) return -1;
    int r = storage_write_block_and_check(storage, index, begin, data, datalen);
    if (r == 0) {
        // piece verified or block written but may not complete entire piece. 
        // If piece complete, caller may query storage_is_piece_complete
        fprintf(stderr, "[client] wrote piece %u OK\n", index);
        if (storage_is_piece_complete(storage, index)) {
            fprintf(stderr, "[peer_wire] piece %u complete and verified\n", index);
            fprintf(stderr, "[client] marking piece %u complete\n", index);
        } else {
            fprintf(stderr, "[peer_wire] wrote block for piece %u begin=%u len=%u\n", index, begin, datalen);
        }
        return 0;
    } else if (r == -2) {
        fprintf(stderr, "[peer_wire] piece %u failed verification\n", index);
        return -2;
    } else {
        fprintf(stderr, "[peer_wire] write error\n");
        return -1;
    }
}

int handle_cancel_msg(int peer_fd, const unsigned char *peerid, uint32_t index, uint32_t begin, uint32_t length, storage_t *storage) {
    (void)peer_fd; (void)peerid; (void)index; (void)begin; (void)length; (void)storage;
    // pending-requests queue in not implemented. Cancel is acknowledged by silence. 
    // TODO: Complete in End-Game
    fprintf(stderr, "[peer_wire] cancel received (ignored) index=%u\n", index);
    return 0;
}
