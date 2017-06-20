#ifndef API_LINUX_REGION_H
#define API_LINUX_REGION_H

#include "api/linux/proctal.h"

void proctal_linux_region_new(struct proctal_linux *pl);

int proctal_linux_region(struct proctal_linux *pl, void **start, void **end);

#endif /* API_LINUX_REGION_H */
