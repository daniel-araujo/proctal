#include "api/proctal.h"

void proctal_pid_set(proctal_t p, int pid)
{
	proctal_impl_pid_set(p, pid);
}

int proctal_pid(proctal_t p)
{
	return proctal_impl_pid(p);
}

