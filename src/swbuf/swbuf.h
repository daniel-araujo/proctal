#ifndef SWBUF_SWBUF_H
#define SWBUF_SWBUF_H

#include <stdlib.h>

/*
 * The swbuf structure. You will want to initialize it by passing a pointer to
 * swbuf_init.
 */
struct swbuf {
	void *curr;
	void *prev;
};

/*
 * Sets the memory allocator.
 *
 * If never called, the default memory allocator is malloc.
 */
void swbuf_set_malloc(void *(*f)(size_t));

/*
 * Sets the memory deallocator.
 *
 * If never called, the default memory deallocator is free.
 */
void swbuf_set_free(void (*f)(void *));

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
	b->curr = swbuf_malloc(size * 2);
	b->prev = (char *) b->curr + size;
}

/*
 * This is an implementation detail. Do not call this function.
 *
 * Returns the start address of the internal buffer.
 */
inline void *swbuf_lead(struct swbuf *b)
{
	return b->curr > b->prev ? b->prev : b->curr;
}

/*
 * Deinitialize an swbuf structure. Do not pass a structure that
 * failed to be initialized or has never been initialized.
 */
inline void swbuf_deinit(struct swbuf *b)
{
	swbuf_free(swbuf_lead(b));
}

/*
 * Returns the size of the buffer.
 */
inline size_t swbuf_size(struct swbuf *b)
{
	if (b->curr > b->prev) {
		return (char *) b->curr - (char *) b->prev;
	} else {
		return (char *) b->prev - (char *) b->curr;
	}
}

/*
 * Returns 1 if an error ocurred, 0 if everything is ok.
 */
inline int swbuf_error(struct swbuf *b)
{
	return swbuf_lead(b) == NULL;
}

/*
 * Returns an offset to the buffer.
 *
 * If offset is 0 or a positive value, this will return an address that can be
 * used up to the size of the buffer minus offset.
 * If offset is a negative value, this will return an address that can be used
 * up to the absolute value of offset (for example, an offset of -12 yields
 * 12) and down to the size of the buffer minus the offset.
 */
inline void *swbuf_address_offset(struct swbuf *b, ssize_t offset)
{
	if (offset >= 0) {
		return (char *) b->curr + offset;
	} else {
		return (char *) b->prev + swbuf_size(b) + offset;
	}
}

/*
 * Swaps the buffer asimetrically.
 */
inline void swbuf_swap(struct swbuf *b)
{
	void *tmp = b->curr;
	b->curr = b->prev;
	b->prev = tmp;
}

#endif /* SWBUF_SWBUF_H */
