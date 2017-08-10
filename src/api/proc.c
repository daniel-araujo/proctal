#include "api/proctal.h"
#include "api/implementation.h"

void proctal_pid_set(proctal_t p, int pid)
{
	proctal_implementation_pid_set(p, pid);
}

int proctal_pid(proctal_t p)
{
	return proctal_implementation_pid(p);
}

