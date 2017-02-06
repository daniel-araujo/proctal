#ifndef CHUNK_CHUNK_H
#define CHUNK_CHUNK_H

#include <stdlib.h>

#include "magic/magic.h"

/*
 * Chunk data structure. Call chunk_init to initialize the struct.
 */
struct chunk {
	size_t size;
	char *curr;
	char *end;
};

/*
 * Initializes a chunk data structure.
 *
 * Takes the start and end addresses of a block of memory and a size for
 * partitioning it in chunks.
 */
inline void chunk_init(struct chunk *c, void *start, void *end, size_t size)
{
	c->size = size;
	c->curr = start;
	c->end = end;
}

/*
 * Deinitializes a chunk data structure.
 */
inline void chunk_deinit(struct chunk *c)
{
}

/*
 * Will return 1 if finished, 0 if there's still more chunks to iterate over.
 */
inline int chunk_finished(struct chunk *c)
{
	return c->curr >= c->end;
}

/*
 * Returns the start address of the current chunk.
 *
 * The function chunk_size returns the size of the returned current chunk.
 *
 * Behavior is left undefined if chunk_finished returns true.
 */
inline void *chunk_offset(struct chunk *c)
{
	return c->curr;
}

/*
 * Size of the current chunk.
 *
 * Behavior is left undefined if chunk_finished returns true.
 */
inline size_t chunk_size(struct chunk *c)
{
	size_t curr_size = c->end - c->curr;

	if (curr_size > c->size) {
		curr_size = c->size;
	}

	return curr_size;
}

/*
 * Moves on to the next chunk.
 *
 * Returns 1 if successful, 0 when no more chunks are available.
 *
 * Behavior is left undefined if chunk_finished returns true.
 */
inline int chunk_next(struct chunk *c)
{
	c->curr += c->size;

	return !chunk_finished(c);
}

#endif /* CHUNK_CHUNK_H */
