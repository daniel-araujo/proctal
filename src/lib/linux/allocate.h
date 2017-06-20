#ifndef LIB_LINUX_ALLOCATE_H
#define LIB_LINUX_ALLOCATE_H

#include "lib/linux/proctal.h"

void *proctal_linux_allocate(struct proctal_linux *pl, size_t size, int permissions);

void proctal_linux_deallocate(struct proctal_linux *pl, void *addr);

#endif /* LIB_LINUX_ALLOCATE_H */
