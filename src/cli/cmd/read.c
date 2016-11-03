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

	proctal_read(p, arg->address, value, size);

	switch (proctal_error(p)) {
	case 0:
		break;

	case PROCTAL_ERROR_PERMISSION_DENIED:
		fprintf(stderr, "No permission.\n");
		proctal_error_ack(p);
		return 1;

	default:
	case PROCTAL_ERROR_READ_FAILURE:
		fprintf(stderr, "Failed to read memory.\n");
		proctal_destroy(p);
		return 1;
	}

	proctal_cmd_val_print(stdout, arg->type, value);
	printf("\n");

	proctal_destroy(p);

	return 0;
}
