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

static int reader_default(void *data, void *src, void *out, size_t size)
{
	return memcpy(out, src, size) != NULL;
}

/*
 * Returns how much data there is to read.
 * Note that this also takes leftvers from previous chunk into account.
 */
static size_t to_be_read(struct srch *srch)
{
	// Current can be negative if there were leftovers from the previous chunk.
	return chunk_size(&srch->chunk) - srch->current;
}

/*
 * Performs the first search.
 */
static void first(struct srch *srch)
{
	srch->current = 0;

	int result = srch->reader(
		NULL,
		chunk_offset(&srch->chunk),
		swbuf_offset(&srch->buf, 0),
		chunk_size(&srch->chunk));

	if (!result) {
		// TODO: Bail.
	}

	char *offset = align_address(chunk_offset(&srch->chunk), srch->data_align);

	srch->current = offset - (char *) chunk_offset(&srch->chunk);

	if (to_be_read(srch) < srch->data_size) {
		// This means there is nothing to iterate over. We will consider this
		// finished.
		chunk_next(&srch->chunk);
	}
}

void srch_init(struct srch *srch, struct srch_config *conf)
{
	srch->error = 0;
	srch->reader = conf->reader ? conf->reader : reader_default;
	srch->source = conf->source;
	srch->source_size = conf->source_size;
	srch->data_align = conf->data_align ? conf->data_align : 1;
	srch->data_size = conf->data_size ? conf->data_size : 1;
	srch->current = 0;

	if (!srch->source) {
		srch->error = SRCH_ERROR_SOURCE_REQUIRED;
		return;
	}

	if (!srch->source_size) {
		srch->error = SRCH_ERROR_SOURCE_SIZE_REQUIRED;
		return;
	}

	if (!conf->buffer_size) {
		srch->error = SRCH_ERROR_BUFFER_SIZE_REQUIRED;
		return;
	}

	if (srch->data_size > conf->buffer_size) {
		srch->error = SRCH_ERROR_DATA_SIZE_LARGER_THAN_BUFFER_SIZE;
		return;
	}

	chunk_init(
		&srch->chunk,
		srch->source,
		(char *) srch->source + srch->source_size,
		conf->buffer_size);

	swbuf_init(&srch->buf, conf->buffer_size);

	first(srch);
}

void srch_deinit(struct srch *srch)
{
	if (srch->error) {
		// All structures should already be deallocated.
		return;
	}

	chunk_deinit(&srch->chunk);
	swbuf_deinit(&srch->buf);
}

int srch_error(struct srch *srch)
{
	return srch->error;
}

int srch_end(struct srch *srch)
{
	return chunk_finished(&srch->chunk);
}

int srch_next(struct srch *srch)
{
	srch->current += srch->data_align;

	// How much data would be read
	size_t leftover = to_be_read(srch);

	if (leftover < srch->data_size) {
		// Can't read any further in this chunk. Will have to move on to the
		// next chunk.

		// Moving on to the next chunk.
		chunk_next(&srch->chunk);

		char *offset = align_address(chunk_offset(&srch->chunk), srch->data_align);

		srch->current = offset - leftover - (char *) chunk_offset(&srch->chunk);

		if (to_be_read(srch) < srch->data_size) {
			// Looks like this chunk doesn't have enough data either. This is
			// the end.
			return 0;
		}

		// Gotta place the contents of the current chunk in a new buffer and
		// turn that buffer active.

		swbuf_swap(&srch->buf);

		int result = srch->reader(
			NULL,
			chunk_offset(&srch->chunk),
			swbuf_offset(&srch->buf, 0),
			chunk_size(&srch->chunk));

		if (!result) {
			// TODO: Bail.
		}
	}

	return 1;
}

ptrdiff_t srch_index(struct srch *srch)
{
	return (char *) srch_offset(srch) - (char *) srch->source;
}

void *srch_offset(struct srch *srch)
{
	return (char *) chunk_offset(&srch->chunk) + srch->current;
}

void *srch_data(struct srch *srch)
{
	return swbuf_offset(&srch->buf, srch->current);
}

size_t srch_data_align(struct srch *srch)
{
	return srch->data_align;
}

size_t srch_data_size(struct srch *srch)
{
	return srch->data_size;
}