#ifndef LINUX_ALLOC_H
#define LINUX_ALLOC_H

#include <linux/proctal.h>

void *proctal_linux_alloc(struct proctal_linux *pl, size_t size, int permissions);

void proctal_linux_dealloc(struct proctal_linux *pl, void *addr);

#endif /* LINUX_ALLOC_H */
