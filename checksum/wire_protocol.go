| "FSND" (4 bytes) | ver: uint16 | flags: uint16 |
| file_size: uint64 (network order) |
| name_len: uint16 | filename (name_len bytes) |
| file_data (file_size bytes) |
| crc32: uint32 (network order) |
| sha1: 20 bytes |
