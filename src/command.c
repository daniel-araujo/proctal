#include <stdio.h>

#include "proctal.h"
#include "command.h"

void proctal_command_read(struct proctal_command_read_arg *arg)
{
	printf("PID %d, Address: %p\n", arg->pid, arg->address);
}

void proctal_command_write(struct proctal_command_write_arg *arg)
{
	printf("PID %d, Address: %p, Value: %d\n", arg->pid, arg->address, arg->value);
}
