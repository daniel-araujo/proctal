#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>

#include "internal.h"
#include "linux/ptrace.h"

int proctal_freeze(proctal p)
{
	return proctal_linux_ptrace_attach(p);
}

int proctal_unfreeze(proctal p)
{
	return proctal_linux_ptrace_detach(p);
}
