#ifndef LIB_LINUX_REGION_H
#define LIB_LINUX_REGION_H

#include "lib/linux/proctal.h"

void proctal_linux_region_new(struct proctal_linux *pl);

int proctal_linux_region(struct proctal_linux *pl, void **start, void **end);

#endif /* LIB_LINUX_REGION_H */
