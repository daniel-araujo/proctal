#include "chunk/chunk.h"

void chunk_init(struct chunk *c, void *start, void *end, size_t size);

void chunk_deinit(struct chunk *c);

int chunk_finished(struct chunk *c);

void *chunk_offset(struct chunk *c);

size_t chunk_size(struct chunk *c);

int chunk_next(struct chunk *c);
