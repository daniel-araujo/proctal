#ifndef LINUX_WATCH_H
#define LINUX_WATCH_H

#include <linux/proctal.h>
#include <linux/ptrace.h>

int proctal_linux_watch(struct proctal_linux *pl, void **addr);

#endif /* LINUX_WATCH_H */
