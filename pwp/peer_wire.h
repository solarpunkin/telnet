#ifndef PEER_WIRE_H
#define PEER_WIRE_H
#include <stdint.h>
#include "storage.h"

/* Called by handshake.c message loop when a request arrives */
int handle_request_msg(int peer_fd, const unsigned char *peerid, uint32_t index, uint32_t begin, uint32_t length, storage_t *storage);

/* Called by handshake.c message loop when a piece message arrives */
int handle_piece_msg(int peer_fd, const unsigned char *peerid, uint32_t index, uint32_t begin, const unsigned char *data, uint32_t datalen, storage_t *storage);

/* Called by handshake.c message loop when a cancel arrives */
int handle_cancel_msg(int peer_fd, const unsigned char *peerid, uint32_t index, uint32_t begin, uint32_t length, storage_t *storage);

/* send helpers */
int send_request_msg(int fd, uint32_t index, uint32_t begin, uint32_t length);
int send_piece_msg(int fd, uint32_t index, uint32_t begin, const void *block, uint32_t blocklen);
int send_cancel_msg(int fd, uint32_t index, uint32_t begin, uint32_t length);

#endif
