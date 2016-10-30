#include <proctal.h>

#include "cmd.h"

int proctal_cmd_write(struct proctal_cmd_write_arg *arg)
{
	proctal p = proctal_create();

	if (p == NULL) {
		fprintf(stderr, "Unable to create an instance of Proctal.\n");
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	size_t size = proctal_cmd_val_size(arg->type);

	if (proctal_write(p, arg->address, arg->value, size) != 0) {
		fprintf(stderr, "Failed to write to memory.\n");
		proctal_destroy(p);
		return 1;
	}

	proctal_destroy(p);

	return 0;
}
