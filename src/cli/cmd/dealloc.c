#include "cli/cmd/dealloc.h"
#include "cli/printer.h"
#include "lib/include/proctal.h"

int cli_cmd_dealloc(struct cli_cmd_dealloc_arg *arg)
{
	proctal p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	proctal_dealloc(p, arg->address);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_destroy(p);

	return 0;
}
