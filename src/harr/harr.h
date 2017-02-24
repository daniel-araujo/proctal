#ifndef HARR_HARR_H
#define HARR_HARR_H

#include <stdlib.h>
#include <string.h>

/*
 * The harr struct. You can initialize it by calling harr_init.
 */
struct harr {
	size_t item_size;
	size_t size;
	char *data;
};

/*
 * This is an implementation detail. Don't call this function.
 *
 * Returns the index of an item.
 */
inline size_t harr_data_index(struct harr *h, int i)
{
	return i * h->item_size;
}

/*
 * Initializes an harr struct.
 *
 * Call harr_deinit to deinitialize.
 */
inline void harr_init(struct harr *h, size_t item_size)
{
	h->item_size = item_size;
	h->size = 0;
	h->data = NULL;
}

/*
 * Deinitializes an harr struct.
 */
inline void harr_deinit(struct harr *h)
{
	if (h->data) {
		free(h->data);
	}
}

/*
 * Returns the current size.
 */
inline int harr_size(struct harr *h)
{
	return h->size;
}

/*
 * Sets the size.
 */
inline int harr_resize(struct harr *h, size_t size)
{
	if (size == h->size) {
		return 1;
	}

	if (size == 0) {
		if (h->data) {
			free(h->data);
			h->data = NULL;
		}

		h->size = size;
		return 1;
	}

	void *new = realloc(h->data, size);

	if (new == NULL) {
		return 0;
	}

	h->size = size;
	h->data = new;
	return 1;
}

/*
 * Returns the address of an item. The address is valid until a resize is
 * made.
 */
inline void *harr_raw(struct harr *h, int i)
{
	return h->data + harr_data_index(h, i);
}

/*
 * Gets the value of an item by its index.
 *
 * The index must be a value smaller than the size.
 */
inline void harr_get(struct harr *h, int i, void *v)
{
	memcpy(v, harr_raw(h, i), h->item_size);
}

/*
 * Sets the value of an item by its index.
 *
 * The index must be a value smaller than the size.
 */
inline void harr_set(struct harr *h, int i, void *v)
{
	memcpy(harr_raw(h, i), v, h->item_size);
}

#endif /* HARR_HARR_H */
