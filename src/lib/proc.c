#include "lib/proctal.h"

void proctal_set_pid(proctal_t p, int pid)
{
	proctal_impl_set_pid(p, pid);
}

int proctal_pid(proctal_t p)
{
	return proctal_impl_pid(p);
}

