#include "magic/magic.h"
#include "api/darr/tests/realloc/util/block-size.h"

size_t block_size(void *address)
{
	return *(((size_t *) address) - 1);
}
