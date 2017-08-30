#include "chunk/chunk.h"

extern inline void chunk_init(
	struct chunk *c,
	void *start,
	void *end,
	size_t size);

extern inline void chunk_deinit(struct chunk *c);

extern inline int chunk_finished(struct chunk *c);

extern inline void *chunk_offset(struct chunk *c);

extern inline size_t chunk_size(struct chunk *c);

extern inline int chunk_next(struct chunk *c);
