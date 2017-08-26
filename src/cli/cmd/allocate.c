#include <stdio.h>

#include "cli/cmd/allocate.h"
#include "cli/printer.h"
#include "api/include/proctal.h"

int cli_cmd_allocate(struct cli_cmd_allocate_arg *arg)
{
	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_close(p);
		return 1;
	}

	proctal_pid_set(p, arg->pid);

	proctal_allocate_read_set(p, arg->read);
	proctal_allocate_write_set(p, arg->write);
	proctal_allocate_execute_set(p, arg->execute);

	void *addr = proctal_allocate(p, arg->size);

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
