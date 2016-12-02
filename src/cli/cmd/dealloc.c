#include <proctal.h>

#include "cmd.h"
#include "printer.h"

int proctal_cmd_dealloc(struct proctal_cmd_dealloc_arg *arg)
{
	proctal p = proctal_create();

	if (proctal_error(p)) {
		proctal_print_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	proctal_dealloc(p, arg->address);

	if (proctal_error(p)) {
		proctal_print_error(p);
		proctal_destroy(p);
		return 1;
	}

	proctal_destroy(p);

	return 0;
}
