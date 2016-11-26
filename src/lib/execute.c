#include <stdlib.h>
#include <stdio.h>
#include <sys/ptrace.h>

#include <proctal.h>
#include <linux/ptrace.h>
#include <linux/alloc.h>

int proctal_execute(proctal p, const char *byte_code, size_t byte_code_length)
{
	return proctal_impl_execute(p, byte_code, byte_code_length);
}
