#ifndef API_LINUX_MEM_H
#define API_LINUX_MEM_H

#include <stdio.h>

#include "api/linux/proctal.h"

size_t proctal_linux_mem_read(struct proctal_linux *pl, void *addr, char *out, size_t size);
size_t proctal_linux_mem_write(struct proctal_linux *pl, void *addr, const char *in, size_t size);

int proctal_linux_mem_swap(struct proctal_linux *pl, void *addr, char *dst, char *src, size_t size);

#endif /* API_LINUX_MEM_H */
