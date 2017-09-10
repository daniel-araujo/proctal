#include "api/linux/execute.h"
#include "api/linux/execute/implementation.h"

int proctal_linux_execute_syscall(struct proctal_linux *pl, int sysnum, void *ret, void *arg1, void *arg2, void *arg3, void *arg4, void *arg5, void *arg6, void *arg7)
{
	return proctal_linux_implementation_execute_syscall(pl, sysnum, ret, arg1, arg2, arg3, arg4, arg5, arg6, arg7);
}
