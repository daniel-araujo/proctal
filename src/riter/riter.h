#ifndef RITER_RITER_H
#define RITER_RITER_H

#include "swbuf/swbuf.h"
#include "chunk/chunk.h"

#define RITER_ERROR_SOURCE_REQUIRED 1
#define RITER_ERROR_SOURCE_SIZE_REQUIRED 2
#define RITER_ERROR_BUFFER_SIZE_REQUIRED 3
#define RITER_ERROR_DATA_SIZE_LARGER_THAN_BUFFER_SIZE 4

// Reader function signature.
// data is user defined data that is passed to the callback.
// src is the address to copy from
// out is the address to copy to
// size is the amount of bytes to copy
typedef int (*riter_reader_fn)(void *data, void *src, void *out, size_t size);

// Must be treated as an opaque data structure. Never access its members.
struct riter {
	// Error code of last failed operation.
	int error;

	// Called to read data from source.
	riter_reader_fn reader;

	// Source of data.
	void *source;

	// Size of the source.
	size_t source_size;

	// Data alignment requirements.
	size_t data_align;

	// Data size.
	size_t data_size;

	// A storage for data chunks. It keeps the previously read chunk in memory.
	// Useful for backtracking.
	struct swbuf buf;

	// Allows us to iterate over the source in chunks.
	struct chunk chunk;

	// Offset in the current chunk.
	ptrdiff_t current;
};

struct riter_config {
	// Called to read data from source. Defaults to memcpy.
	riter_reader_fn reader;

	// Source of data.
	void *source;

	// Size of the source.
	size_t source_size;

	// Data alignment requirements.
	size_t data_align;

	// Data size.
	size_t data_size;

	// Read buffer size.
	size_t buffer_size;
};

/*
 * Initializes search. Searches for the first one immediately.
 */
void riter_init(struct riter *r, struct riter_config *conf);

/*
 * Disposes resources. Call this when done.
 */
void riter_deinit(struct riter *r);

/*
 * Returns error code if last operation failed.
 */
int riter_error(struct riter *r);

/*
 * Checks whether we've reached the end.
 * Returns 1 if true, 0 otherwise.
 */
int riter_end(struct riter *r);

/*
 * Moves on to the next data.
 * Returns 1 if possible, 0 when end is reached.
 */
int riter_next(struct riter *r);

/*
 * Index into source.
 */
ptrdiff_t riter_index(struct riter *r);

/*
 * Offset into source.
 */
void *riter_offset(struct riter *r);

/*
 * Returns address to current data.
 * Note that this is not an address to the source. Call riter_offset, instead.
 */
void *riter_data(struct riter *r);

/*
 * Returns data alignment requirement in use.
 */
size_t riter_data_align(struct riter *r);

/*
 * Returns data size.
 */
size_t riter_data_size(struct riter *r);

#endif /* RITER_RITER_H */
