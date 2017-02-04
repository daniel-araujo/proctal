#ifndef LIB_LINUX_ALLOC_H
#define LIB_LINUX_ALLOC_H

#include "lib/linux/proctal.h"

void *proctal_linux_alloc(struct proctal_linux *pl, size_t size, int permissions);

void proctal_linux_dealloc(struct proctal_linux *pl, void *addr);

#endif /* LIB_LINUX_ALLOC_H */
