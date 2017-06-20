#include "lib/proctal.h"

void *proctal_alloc(proctal_t p, size_t size, int perm)
{
	return proctal_impl_alloc(p, size, perm);
}

void proctal_dealloc(proctal_t p, void *addr)
{
	proctal_impl_dealloc(p, addr);
}
