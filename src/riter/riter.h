#ifndef CLI_SRCH_H
#define CLI_SRCH_H

#include "swbuf/swbuf.h"
#include "chunk/chunk.h"

#define SRCH_ERROR_SOURCE_REQUIRED 1
#define SRCH_ERROR_SOURCE_SIZE_REQUIRED 2
#define SRCH_ERROR_BUFFER_SIZE_REQUIRED 3
#define SRCH_ERROR_DATA_SIZE_LARGER_THAN_BUFFER_SIZE 4

// Reader function signature.
// data is user defined data that is passed to the callback.
// src is the address to copy from
// out is the address to copy to
// size is the amount of bytes to copy
typedef int (*srch_reader_fn)(void *data, void *src, void *out, size_t size);

// Must be treated as an opaque data structure. Never access its members.
struct srch {
	// Error code of last failed operation.
	int error;

	// Called to read data from source.
	srch_reader_fn reader;

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

struct srch_config {
	// Called to read data from source. Defaults to memcpy.
	srch_reader_fn reader;

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
void srch_init(struct srch *srch, struct srch_config *conf);

/*
 * Disposes resources. Call this when done.
 */
void srch_deinit(struct srch *srch);

/*
 * Returns error code if last operation failed.
 */
int srch_error(struct srch *srch);

/*
 * Checks whether we've reached the end.
 * Returns 1 if true, 0 otherwise.
 */
int srch_end(struct srch *srch);

/*
 * Moves on to the next data.
 * Returns 1 if possible, 0 when end is reached.
 */
int srch_next(struct srch *srch);

/*
 * Index into source.
 */
size_t srch_index(struct srch *srch);

/*
 * Offset into source.
 */
void *srch_offset(struct srch *srch);

/*
 * Returns address to current data.
 */
void *srch_data(struct srch *srch);

/*
 * Returns data alignment requirement in use.
 */
size_t srch_data_align(struct srch *srch);

/*
 * Returns data size.
 */
size_t srch_data_size(struct srch *srch);

#endif /* CLI_SRCH_H */
