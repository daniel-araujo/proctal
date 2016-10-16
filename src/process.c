#include <stdlib.h>

struct proctal_process {
	int pid;
};

typedef struct proctal_process *proctal_process;
typedef void *proctal_process_memory_address;

proctal_process proctal_process_create(int pid)
{
	proctal_process process = (proctal_process) malloc(sizeof *process);

	if (process == NULL) {
		return NULL;
	}

	process->pid = pid;

	return process;
}

int proctal_process_get_pid(proctal_process process)
{
	return process->pid;
}

void proctal_process_destroy(proctal_process process)
{
	free(process);
}

proctal_process_memory_address proctal_process_memory_address_create(
	proctal_process process,
	void *addr)
{
	return (proctal_process_memory_address) addr;
}

long proctal_process_memory_address_get_offset(proctal_process_memory_address address)
{
	return (long) address;
}

void proctal_process_memory_address_destroy(proctal_process_memory_address process)
{
}
