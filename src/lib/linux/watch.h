#ifndef LINUX_WATCH_H
#define LINUX_WATCH_H

#include <linux/proctal.h>
#include <linux/ptrace.h>

struct proctal_linux_watch {
	struct proctal_watch pw;

	struct proctal_linux *pl;
};

void proctal_linux_watch_init(struct proctal_linux *pl, struct proctal_linux_watch *plw);

void proctal_linux_watch_deinit(struct proctal_linux *pl, struct proctal_linux_watch *plw);

int proctal_linux_watch_next(struct proctal_linux_watch *plw, void **addr);

#endif /* LINUX_WATCH_H */
