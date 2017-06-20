#include "lib/proctal.h"

void *proctal_allocate(proctal_t p, size_t size, int perm)
{
	return proctal_impl_allocate(p, size, perm);
}

void proctal_deallocate(proctal_t p, void *addr)
{
	proctal_impl_deallocate(p, addr);
}
