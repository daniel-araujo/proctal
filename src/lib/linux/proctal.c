#include <linux/proctal.h>

void proctal_linux_init(struct proctal_linux *pl)
{
	proctal_init(&pl->p);

	pl->ptrace = 0;
	pl->memr = NULL;
	pl->memw = NULL;
}

void proctal_linux_deinit(struct proctal_linux *pl)
{
	if (pl == NULL) {
		return;
	}

	proctal_deinit(&pl->p);

	if (pl->memr) {
		fclose(pl->memr);
	}

	if (pl->memw) {
		fclose(pl->memw);
	}
}

void proctal_linux_set_pid(struct proctal_linux *pl, pid_t pid)
{
	if (pl->memr) {
		fclose(pl->memr);
		pl->memr = NULL;
	}

	if (pl->memw) {
		fclose(pl->memw);
		pl->memw = NULL;
	}

	pl->pid = pid;
}

pid_t proctal_linux_pid(struct proctal_linux *pl)
{
	return pl->pid;
}
