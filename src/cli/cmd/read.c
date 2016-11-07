#include <proctal.h>

#include "cmd.h"

static inline void print_separator(struct proctal_cmd_read_arg *arg)
{
	switch (proctal_cmd_val_attr_type(arg->value_attr)) {
	case PROCTAL_CMD_VAL_TYPE_TEXT:
		break;

	case PROCTAL_CMD_VAL_TYPE_BYTE:
	case PROCTAL_CMD_VAL_TYPE_INTEGER:
	case PROCTAL_CMD_VAL_TYPE_IEEE754:
	case PROCTAL_CMD_VAL_TYPE_ADDRESS:
	default:
		printf("\n");
		break;
	}
}

static inline void print_ending(struct proctal_cmd_read_arg *arg)
{
	printf("\n");
}

int proctal_cmd_read(struct proctal_cmd_read_arg *arg)
{
	proctal p = proctal_create();

	switch (proctal_error(p)) {
	case 0:
		break;

	case PROCTAL_ERROR_OUT_OF_MEMORY:
		fprintf(stderr, "Out of memory.\n");
		proctal_destroy(p);
		return 1;

	default:
		fprintf(stderr, "Unable to create an instance of Proctal.\n");
		proctal_destroy(p);
		return 1;
	}

	proctal_set_pid(p, arg->pid);

	proctal_cmd_val value = proctal_cmd_val_create(arg->value_attr);
	size_t size = proctal_cmd_val_sizeof(value);
	char *output = proctal_cmd_val_addr(value);

	char *addr = (char *) arg->address;
	for (size_t i = 0; i < arg->array; ++i) {
		proctal_read(p, addr, output, size);

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

		proctal_cmd_val_print(value, stdout);

		addr += size;

		if (i < arg->array - 1) {
			print_separator(arg);
		}
	}

	print_ending(arg);

	proctal_destroy(p);

	return 0;
}
