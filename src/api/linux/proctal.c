#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"
#include "api/linux/address.h"
#include "api/linux/region.h"

void proctal_linux_init(struct proctal_linux *pl)
{
	proctal_init(&pl->p);

	pl->mem = NULL;

	pl->ptrace.count = 0;
	darr_init(&pl->ptrace.tasks, sizeof(struct proctal_linux_ptrace_task));

	pl->address.started = 0;

	pl->region.started = 0;
}

void proctal_linux_deinit(struct proctal_linux *pl)
{
	proctal_deinit(&pl->p);

	if (pl->mem) {
		fclose(pl->mem);
	}

	proctal_linux_ptrace_detach_force(pl);
	darr_deinit(&pl->ptrace.tasks);

	proctal_linux_scan_address_stop(pl);

	proctal_linux_scan_region_stop(pl);
}

void proctal_linux_pid_set(struct proctal_linux *pl, pid_t pid)
{
	if (pl->mem) {
		fclose(pl->mem);
		pl->mem = NULL;
	}

	proctal_linux_ptrace_detach_force(pl);

	pl->pid = pid;
}

pid_t proctal_linux_pid(struct proctal_linux *pl)
{
	return pl->pid;
}
