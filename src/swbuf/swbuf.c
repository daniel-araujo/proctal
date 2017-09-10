#include "swbuf/swbuf.h"

static void *(*alloc)(size_t) = malloc;
static void (*dealloc)(void *) = free;

extern inline void swbuf_init(struct swbuf *b, size_t size);

extern inline void *swbuf_lead(struct swbuf *b);

extern inline void swbuf_deinit(struct swbuf *b);

extern inline int swbuf_error(struct swbuf *b);

extern inline size_t swbuf_size(struct swbuf *b);

extern inline void swbuf_swap(struct swbuf *b);

extern inline void *swbuf_offset(struct swbuf *b, ptrdiff_t offset);

void swbuf_malloc_set(void *(*f)(size_t))
{
	alloc = f;
}

void swbuf_free_set(void (*f)(void *))
{
	dealloc = f;
}

void *swbuf_malloc(size_t size)
{
	return alloc(size);
}

void swbuf_free(void *b)
{
	dealloc(b);
}
