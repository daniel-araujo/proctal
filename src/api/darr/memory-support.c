#include <string.h>

#include "api/darr/memory-support.h"
#include "api/proctal.h"
#include "magic/magic.h"

void *proctal_darr_global_realloc(void *address, size_t size)
{
	if (address == NULL) {
		void *n = proctal_global_malloc(size + sizeof(size));

		if (n == NULL) {
			return NULL;
		}

		DEREF(size_t, n) = size;

		return (size_t *) n + 1;
	} else {
		size_t old_size = *((size_t *) address - 1);

		if (size == old_size) {
			// Same size. No need to do anything.
			return address;
		} else if (size < old_size && size > (old_size - old_size / 3)) {
			// Not worth creating a smaller block.
			return address;
		}

		void *n = proctal_global_malloc(size + sizeof(size));

		if (n == NULL) {
			return NULL;
		}

		DEREF(size_t, n) = size;
		memcpy((size_t *) n + 1, address, size > old_size ? old_size : size);

		proctal_darr_global_free(address);

		return (size_t *) n + 1;
	}
}

void proctal_darr_global_free(void *address)
{
	proctal_global_free((size_t *) address - 1);
}
