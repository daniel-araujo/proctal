#include "api/proctal.h"
#include "api/implementation.h"

void *proctal_allocate(proctal_t p, size_t size, int perm)
{
	return proctal_implementation_allocate(p, size, perm);
}

void proctal_deallocate(proctal_t p, void *addr)
{
	proctal_implementation_deallocate(p, addr);
}
