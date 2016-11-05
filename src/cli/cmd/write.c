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

	size_t size = proctal_cmd_val_sizeof(arg->value);
	char *input = proctal_cmd_val_addr(arg->value);

	proctal_write(p, arg->address, input, size);

	switch (proctal_error(p)) {
	case 0:
		break;

	case PROCTAL_ERROR_PERMISSION_DENIED:
		fprintf(stderr, "No permission.\n");
		proctal_error_ack(p);
		return 1;

	default:
	case PROCTAL_ERROR_WRITE_FAILURE:
		fprintf(stderr, "Failed to write to memory.\n");
		proctal_destroy(p);
		return 1;
	}

	proctal_destroy(p);

	return 0;
}
