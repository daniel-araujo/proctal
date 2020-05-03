#ifndef SWBUF_SWBUF_H
#define SWBUF_SWBUF_H

#include <stdlib.h>
#include <stddef.h>
#include <string.h>

/*
 * The swbuf structure. You will want to initialize it by passing a pointer to
 * swbuf_init.
 */
struct swbuf {
	// The two sides are allocated in the same block. The left side starts at
	// this address, the right side starts at this address plus the size of the
	// buffer.
	void *buffer;

	// Reserved for the swap operation. This side starts at the buffer address
	// plus 2 times its size.
	void *swap;
};

/*
 * Sets the memory allocator.
 *
 * If never called, the default memory allocator is malloc.
 */
void swbuf_malloc_set(void *(*f)(size_t));

/*
 * Sets the memory deallocator.
 *
 * If never called, the default memory deallocator is free.
 */
void swbuf_free_set(void (*f)(void *));

/*
 * This is an implementation detail. Do not call this function.
 *
 * Allocates a block of memory using swbuf's registered memory allocator.
 */
void *swbuf_malloc(size_t size);

/*
 * This is an implementation detail. Do not call this function.
 *
 * Deallocates a block of memory using swbuf's registered memory deallocator.
 */
void swbuf_free(void *b);

/*
 * Initiates an swbuf structure. Takes the size of the buffer.
 *
 * Call swbuf_error to check if something failed.
 */
inline void swbuf_init(struct swbuf *b, size_t size)
{
	b->buffer = swbuf_malloc(size * 3);
	b->swap = (char *) b->buffer + size * 2;
}

/*
 * Deinitialize an swbuf structure. Do not pass a structure that
 * failed to be initialized or has never been initialized.
 */
inline void swbuf_deinit(struct swbuf *b)
{
	if (b->buffer) {
		swbuf_free(b->buffer);
	}
}

/*
 * Returns the size of the buffer.
 */
inline size_t swbuf_size(struct swbuf *b)
{
	return ((char *) b->swap - (char *) b->buffer) / 2;
}

/*
 * Returns 1 if an error ocurred, 0 if everything is ok.
 */
inline int swbuf_error(struct swbuf *b)
{
	return b->buffer == NULL;
}

/*
 * Returns a pointer to the buffer.
 *
 * If offset is 0 or a positive value, this will return an address that can be
 * used up to the size of the buffer minus offset.
 * If offset is a negative value, this will return an address that can be used
 * up to the absolute value of offset (for example, an offset of -12 yields
 * 12) and down to the size of the buffer minus the absolute value of offset.
 */
inline void *swbuf_offset(struct swbuf *b, ptrdiff_t offset)
{
	return (char *) b->buffer + swbuf_size(b) + offset;
}

/*
 * Swaps the buffer.
 */
inline void swbuf_swap(struct swbuf *b)
{
	size_t size = swbuf_size(b);

	void *sideA = b->buffer;
	void *sideB = (char *) b->buffer + size;

	memmove(b->swap, sideA, size);
	memmove(sideA, sideB, size);
	memmove(sideB, b->swap, size);
}

#endif /* SWBUF_SWBUF_H */
