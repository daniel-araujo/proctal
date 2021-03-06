#ifndef API_LINUX_ADDRESS_H
#define API_LINUX_ADDRESS_H

#include <stdio.h>

#include "api/linux/proctal.h"
#include "api/linux/proc.h"

void proctal_linux_scan_address_start(struct proctal_linux *pl);

void proctal_linux_scan_address_stop(struct proctal_linux *pl);

int proctal_linux_scan_address_next(struct proctal_linux *pl, void **address);

#endif /* API_LINUX_ADDRESS_H */
