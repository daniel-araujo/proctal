#ifndef API_LINUX_ALLOCATE_H
#define API_LINUX_ALLOCATE_H

#include "api/linux/proctal.h"

void *proctal_linux_allocate(struct proctal_linux *pl, size_t size);

void proctal_linux_deallocate(struct proctal_linux *pl, void *address);

#endif /* API_LINUX_ALLOCATE_H */
