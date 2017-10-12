#ifndef API_DARR_TESTS_REALLOC_UTIL_BLOCK_SIZE_H
#define API_DARR_TESTS_REALLOC_UTIL_BLOCK_SIZE_H

#include <stdlib.h>

/**
 * Retrieves the size of the block returned by proctal_global_realloc.
 */
size_t block_size(void *address);

#endif /* API_DARR_TESTS_REALLOC_UTIL_BLOCK_SIZE_H */
