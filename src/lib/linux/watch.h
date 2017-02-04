#ifndef LIB_LINUX_WATCH_H
#define LIB_LINUX_WATCH_H

#include "lib/linux/proctal.h"
#include "lib/linux/ptrace.h"

int proctal_linux_watch(struct proctal_linux *pl, void **addr);

#endif /* LIB_LINUX_WATCH_H */
