#include "swbuf/swbuf.h"

static void *(*alloc)(size_t) = malloc;
static void (*dealloc)(void *) = free;

void swbuf_init(struct swbuf *b, size_t size);

void *swbuf_lead(struct swbuf *b);

void swbuf_deinit(struct swbuf *b);

int swbuf_error(struct swbuf *b);

size_t swbuf_size(struct swbuf *b);

void swbuf_swap(struct swbuf *b);

void *swbuf_address_offset(struct swbuf *b, ssize_t offset);

void swbuf_set_malloc(void *(*f)(size_t))
{
	alloc = f;
}

void swbuf_set_free(void (*f)(void *))
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
