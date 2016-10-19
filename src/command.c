#include <stdio.h>
#include <sys/uio.h>

#include "proctal.h"
#include "command.h"

void proctal_command_read(struct proctal_command_read_arg *arg)
{
	int val;

	switch (proctal_read_int(arg->pid, arg->address, &val)) {
	case 0:
		printf("%d\n", val);
		break;
	default:
		fprintf(stderr, "Failed to read memory.\n");
	}
}

void proctal_command_write(struct proctal_command_write_arg *arg)
{
	switch (proctal_write_int(arg->pid, arg->address, arg->value)) {
	case 0:
		break;
	default:
		fprintf(stderr, "Failed to write to memory.\n");
	}
}
