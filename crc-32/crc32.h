#ifndef CRC32_H
#define CRC32_H

#include <stddef.h>
#include <stdint.h>

uint32_t xcrc32(const unsigned char *buf, int len, uint32_t init);

#endif