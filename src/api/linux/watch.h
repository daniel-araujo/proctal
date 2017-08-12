#ifndef API_LINUX_WATCH_H
#define API_LINUX_WATCH_H

#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"

void proctal_linux_watch_start(struct proctal_linux *pl);

void proctal_linux_watch_stop(struct proctal_linux *pl);

int proctal_linux_watch(struct proctal_linux *pl, void **addr);

#endif /* API_LINUX_WATCH_H */
