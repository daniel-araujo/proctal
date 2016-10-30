#include <proctal.h>

#include "cmd.h"

int proctal_cmd_read(struct proctal_cmd_read_arg *arg)
{
	proctal p = proctal_create();

	if (p == NULL) {
		fprintf(stderr, "Unable to create an instance of Proctal.\n");
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	size_t size = proctal_cmd_val_size(arg->type);
	char value[size];

	if (proctal_read(p, arg->address, value, size) != 0) { \
		fprintf(stderr, "Failed to read memory.\n");
		proctal_destroy(p);
		return 1;
	}

	proctal_cmd_val_print(stdout, arg->type, value);
	printf("\n");

	proctal_destroy(p);

	return 0;
}
