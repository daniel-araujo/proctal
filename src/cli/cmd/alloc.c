#include <stdio.h>

#include "cli/cmd/alloc.h"
#include "cli/printer.h"
#include "lib/include/proctal.h"

static int make_permission(struct cli_cmd_alloc_arg *arg)
{
	int perm = 0;

	if (arg->read) {
		perm |= PROCTAL_ALLOC_PERM_READ;
	}

	if (arg->write) {
		perm |= PROCTAL_ALLOC_PERM_WRITE;
	}

	if (arg->execute) {
		perm |= PROCTAL_ALLOC_PERM_EXECUTE;
	}

	return perm;
}

int cli_cmd_alloc(struct cli_cmd_alloc_arg *arg)
{
	proctal p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	int perm = make_permission(arg);

	void *addr = proctal_alloc(p, arg->size, perm);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	cli_print_address(addr);
	printf("\n");

	proctal_destroy(p);

	return 0;
}
