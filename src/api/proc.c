#include "api/proctal.h"
#include "api/implementation.h"

void proctal_pid_set(struct proctal *p, int pid)
{
	proctal_implementation_pid_set(p, pid);
}

int proctal_pid(struct proctal *p)
{
	return proctal_implementation_pid(p);
}

