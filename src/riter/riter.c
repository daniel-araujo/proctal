#include <stdint.h>
#include <string.h>

#include "src/riter/riter.h"

/*
 * For aligning. Returns the address in the correct offset. If the address is
 * correctly aligned then it will be returned as is. This function will only
 * move the address forward, never backwards.
 */
static inline void *align_address(void *address, size_t align)
{
	ptrdiff_t offset = ((uintptr_t) address % align);

	if (offset != 0) {
		offset = align - offset;
	}

	return (void *) ((char *) address + offset);
}

/*
 * The default reader. Just reads from main memory.
 */
static int reader_default(void *user, void *src, void *out, size_t size)
{
	return memcpy(out, src, size) != NULL;
}

/*
 * Returns how much data there is to read.
 * Note that this also takes leftvers from previous chunk into account.
 */
static size_t to_be_read(struct riter *r)
{
	// Current can be negative if there were leftovers from the previous chunk.
	return chunk_size(&r->chunk) - r->current;
}

/*
 * Performs the first search.
 */
static void first(struct riter *r)
{
	r->current = 0;

	int result = r->reader(
		r->user,
		chunk_offset(&r->chunk),
		swbuf_offset(&r->buf, 0),
		chunk_size(&r->chunk));

	if (!result) {
		// Hard failure.
		riter_deinit(r);
		r->error = RITER_ERROR_READ_FAILURE;
		return;
	}

	char *offset = align_address(chunk_offset(&r->chunk), r->data_align);

	r->current = offset - (char *) chunk_offset(&r->chunk);

	if (to_be_read(r) < r->data_size) {
		// This means there is nothing to iterate over. We will consider this
		// finished.
		chunk_next(&r->chunk);
	}
}

void riter_init(struct riter *r, struct riter_config *conf)
{
	r->error = 0;
	r->reader = conf->reader ? conf->reader : reader_default;
	r->source = conf->source;
	r->source_size = conf->source_size;
	r->data_align = conf->data_align ? conf->data_align : 1;
	r->data_size = conf->data_size ? conf->data_size : 1;
	r->user = conf->user;
	r->current = 0;

	if (!r->source) {
		r->error = RITER_ERROR_SOURCE_REQUIRED;
		return;
	}

	if (!r->source_size) {
		r->error = RITER_ERROR_SOURCE_SIZE_REQUIRED;
		return;
	}

	if (!conf->buffer_size) {
		r->error = RITER_ERROR_BUFFER_SIZE_REQUIRED;
		return;
	}

	if (r->data_size > conf->buffer_size) {
		r->error = RITER_ERROR_DATA_SIZE_LARGER_THAN_BUFFER_SIZE;
		return;
	}

	chunk_init(
		&r->chunk,
		r->source,
		(char *) r->source + r->source_size,
		conf->buffer_size);

	swbuf_init(&r->buf, conf->buffer_size);

	first(r);
}

void riter_deinit(struct riter *r)
{
	if (r->error) {
		// All structures should already be deallocated.
		return;
	}

	chunk_deinit(&r->chunk);
	swbuf_deinit(&r->buf);
}

int riter_error(struct riter *r)
{
	return r->error;
}

int riter_end(struct riter *r)
{
	return chunk_finished(&r->chunk);
}

int riter_next(struct riter *r)
{
	r->current += r->data_align;

	// How much data would be read
	size_t leftover = to_be_read(r);

	if (leftover < r->data_size) {
		// Can't read any further in this chunk. Will have to move on to the
		// next chunk.

		// Moving on to the next chunk.
		chunk_next(&r->chunk);

		char *offset = align_address(chunk_offset(&r->chunk), r->data_align);

		r->current = offset - leftover - (char *) chunk_offset(&r->chunk);

		if (to_be_read(r) < r->data_size) {
			// Looks like this chunk doesn't have enough data either. This is
			// the end.
			return 0;
		}

		// Gotta place the contents of the current chunk in a new buffer and
		// turn that buffer active.

		swbuf_swap(&r->buf);

		int result = r->reader(
			r->user,
			chunk_offset(&r->chunk),
			swbuf_offset(&r->buf, 0),
			chunk_size(&r->chunk));

		if (!result) {
			// Hard failure.
			riter_deinit(r);
			r->error = RITER_ERROR_READ_FAILURE;
			return 0;
		}
	}

	return 1;
}

ptrdiff_t riter_index(struct riter *r)
{
	return (char *) riter_offset(r) - (char *) r->source;
}

void *riter_offset(struct riter *r)
{
	return (char *) chunk_offset(&r->chunk) + r->current;
}

void *riter_data(struct riter *t)
{
	return swbuf_offset(&t->buf, t->current);
}

size_t riter_data_align(struct riter *t)
{
	return t->data_align;
}

size_t riter_data_size(struct riter *r)
{
	return r->data_size;
}