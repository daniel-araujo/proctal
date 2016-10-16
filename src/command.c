#include <stdio.h>
#include <sys/uio.h>

#include "proctal.h"
#include "command.h"

void proctal_command_read(struct proctal_command_read_arg *arg)
{
	proctal_process process = proctal_process_create(arg->pid);
	proctal_process_memory_address address = proctal_process_memory_address_create(process, arg->address);

	int i = proctal_read_memory_int(process, address);

	printf("%d\n", i);
}

void proctal_command_write(struct proctal_command_write_arg *arg)
{
	proctal_process process = proctal_process_create(arg->pid);
	proctal_process_memory_address address = proctal_process_memory_address_create(process, arg->address);

	proctal_write_memory_int(process, address, arg->value);
}
