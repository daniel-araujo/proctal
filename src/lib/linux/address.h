#ifndef LIB_LINUX_ADDRESS_H
#define LIB_LINUX_ADDRESS_H

#include <stdio.h>

#include "lib/linux/proctal.h"
#include "lib/linux/proc.h"

void proctal_linux_address_new(struct proctal_linux *pl);

int proctal_linux_address(struct proctal_linux *pl, void **addr);

#endif /* LIB_LINUX_ADDRESS_H */
