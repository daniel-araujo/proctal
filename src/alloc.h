#ifndef ALLOC_H
#define ALLOC_H

#include <stdlib.h>

void *proctal_alloc(size_t size);

void proctal_dealloc(void *addr);

#endif /* ALLOC_H */
