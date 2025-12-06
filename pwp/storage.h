#ifndef STORAGE_H
#define STORAGE_H

#include <stddef.h>
#include <stdint.h>

#define MAX_TORRENT_NAME 256

typedef struct {
    char name[MAX_TORRENT_NAME];   // torrent name / id
    uint64_t total_length;         // total bytes of file (single-file mode)
    uint32_t piece_len;           // piece length (bytes)
    uint32_t num_pieces;
    unsigned char *pieces_hashes; // pointer to raw piece-hash bytes (num_pieces * hash_len)
    size_t piece_hash_len;        // 32 for SHA-256, 20 for legacy SHA-1
    char storage_path[512];       // path to the data file
    unsigned char *have_bits;     // bitfield (num_pieces bits) 
} storage_t;

/* initialize storage based on torrent metadata buffer.
   Parameters:
     storage: pointer to storage_t to initialize (allocated by caller)
     info_buf, info_len: exact bencoded "info" slice used for hashing and parsing
     torrent_name: used to form storage file name (optional)
   Returns 0 on success.
*/
int storage_init_from_info(storage_t *storage, const unsigned char *info_buf, size_t info_len, const char *torrent_name);

/* free storage internals (not the struct itself) */
void storage_free(storage_t *s);

/* generate bitfield into caller buffer (bits packed, MSB first like spec).
   Caller must allocate at least (num_pieces+7)/8 bytes.
*/
int storage_get_bitfield(storage_t *s, unsigned char *out_bits, size_t out_len);

/* read a block from a piece into buf.
   index: piece index (0-based)
   begin: offset into piece
   buf: destination buffer (length bytes)
   length: number of bytes to read
   Returns 0 on success.
*/
int storage_read_block(storage_t *s, uint32_t index, uint32_t begin, void *buf, uint32_t length);

/* write a block into a piece (atomic to file at offset). If this completes the piece,
   verify SHA-256 and mark it as complete.
   Returns:
     0 on success (block written, piece maybe complete)
    -1 on IO error
    -2 if hash verification failed (piece invalid) -> caller may delete piece blocks
*/
int storage_write_block_and_check(storage_t *s, uint32_t index, uint32_t begin, const void *buf, uint32_t length);

/* mark piece as complete (used internally) */
int storage_is_piece_complete(storage_t *s, uint32_t index);

/* quickly get piece length (last piece may be shorter) */
uint32_t storage_piece_size(storage_t *s, uint32_t index);

/* return pointer to storage struct internals if needed (readonly) */
uint32_t storage_num_pieces(storage_t *s);
uint32_t storage_piece_length(storage_t *s);

#endif // STORAGE_H
