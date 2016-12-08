#ifndef LINUX_ADDRESS_H
#define LINUX_ADDRESS_H

#include <stdio.h>

#include <linux/proctal.h>
#include <linux/proc.h>

void proctal_linux_address_new(struct proctal_linux *pl);

int proctal_linux_address(struct proctal_linux *pl, void **addr);

#endif /* LINUX_ADDRESS_H */
