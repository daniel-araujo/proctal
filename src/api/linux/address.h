#ifndef API_LINUX_ADDRESS_H
#define API_LINUX_ADDRESS_H

#include <stdio.h>

#include "api/linux/proctal.h"
#include "api/linux/proc.h"

void proctal_linux_address_new(struct proctal_linux *pl);

int proctal_linux_address(struct proctal_linux *pl, void **addr);

#endif /* API_LINUX_ADDRESS_H */
