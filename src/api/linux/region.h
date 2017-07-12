#ifndef API_LINUX_REGION_H
#define API_LINUX_REGION_H

#include "api/linux/proctal.h"

void proctal_linux_scan_region_start(struct proctal_linux *pl);

void proctal_linux_scan_region_stop(struct proctal_linux *pl);

int proctal_linux_scan_region(struct proctal_linux *pl, void **start, void **end);

#endif /* API_LINUX_REGION_H */
