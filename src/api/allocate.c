#include "api/proctal.h"
#include "api/implementation.h"

void *proctal_allocate(struct proctal *p, size_t size, int perm)
{
	return proctal_implementation_allocate(p, size, perm);
}

void proctal_deallocate(struct proctal *p, void *addr)
{
	proctal_implementation_deallocate(p, addr);
}
