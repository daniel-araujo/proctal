#include "cli/cmd/deallocate.h"
#include "cli/printer.h"
#include "api/include/proctal.h"

int cli_cmd_deallocate(struct cli_cmd_deallocate_arg *arg)
{
	proctal_t p = proctal_create();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	proctal_deallocate(p, arg->address);

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_destroy(p);

	return 0;
}
