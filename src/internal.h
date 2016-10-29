#ifndef INTERNAL_H
#define INTERNAL_H

#include "proctal.h"

FILE *proctal_memr(proctal p);
FILE *proctal_memw(proctal p);

/*
 * Allocate and deallocate memory.
 */
void *proctal_alloc(proctal p, size_t size);
void proctal_dealloc(proctal p, void *addr);

#endif /* INTERNAL_H */
