#include <stdio.h>

#include "cli/cmd/allocate.h"
#include "cli/printer.h"
#include "api/include/proctal.h"

static int make_permission(struct cli_cmd_allocate_arg *arg)
{
	int perm = 0;

	if (arg->read) {
		perm |= PROCTAL_ALLOCATE_PERM_READ;
	}

	if (arg->write) {
		perm |= PROCTAL_ALLOCATE_PERM_WRITE;
	}

	if (arg->execute) {
		perm |= PROCTAL_ALLOCATE_PERM_EXECUTE;
	}

	return perm;
}

int cli_cmd_allocate(struct cli_cmd_allocate_arg *arg)
{
	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_close(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	int perm = make_permission(arg);

	void *addr = proctal_allocate(p, arg->size, perm);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_close(p);
		return 1;
	}

	cli_print_address(addr);
	printf("\n");

	proctal_close(p);

	return 0;
}
