#ifndef LINUX_REGION_H
#define LINUX_REGION_H

#include <linux/proctal.h>

void proctal_linux_region_new(struct proctal_linux *pl);

int proctal_linux_region(struct proctal_linux *pl, void **start, void **end);

#endif /* LINUX_REGION_H */
