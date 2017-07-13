#include "cli/cmd/deallocate.h"
#include "cli/printer.h"
#include "api/include/proctal.h"

int cli_cmd_deallocate(struct cli_cmd_deallocate_arg *arg)
{
	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_close(p);
		return 1;
	}

	proctal_pid_set(p, arg->pid);

	proctal_deallocate(p, arg->address);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_close(p);
		return 1;
	}

	proctal_close(p);

	return 0;
}
