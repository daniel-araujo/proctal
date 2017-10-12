#ifndef API_DARR_MEMORY_SUPPORT_H
#define API_DARR_MEMORY_SUPPORT_H

#include <stdlib.h>

/*
 * Reallocates memory for darr using the user provided malloc function.
 */
void *proctal_darr_global_realloc(void *address, size_t size);

/*
 * Frees memory for darr using the user provided free function.
 */
void proctal_darr_global_free(void *address);

#endif /* API_DARR_MEMORY_SUPPORT_H */
