#ifndef LINUX_ALLOC_H
#define LINUX_ALLOC_H

#include <linux/proctal.h>

#define PROCTAL_LINUX_ALLOC_WRITE 1
#define PROCTAL_LINUX_ALLOC_READ 2
#define PROCTAL_LINUX_ALLOC_EXECUTE 4

void *proctal_linux_alloc(struct proctal_linux *pl, size_t size, int permissions);

int proctal_linux_dealloc(struct proctal_linux *pl, void *addr);

#endif /* LINUX_ALLOC_H */
