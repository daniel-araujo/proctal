#include "api/proctal.h"
#include "api/implementation.h"

void *proctal_allocate(struct proctal *p, size_t size)
{
	return proctal_implementation_allocate(p, size);
}

int proctal_allocate_read(struct proctal *p)
{
	return p->allocate.read;
}

void proctal_allocate_read_set(struct proctal *p, int read)
{
	p->allocate.read = read != 0;
}

int proctal_allocate_write(struct proctal *p)
{
	return p->allocate.write;
}

void proctal_allocate_write_set(struct proctal *p, int write)
{
	p->allocate.write = write != 0;
}

int proctal_allocate_execute(struct proctal *p)
{
	return p->allocate.execute;
}

void proctal_allocate_execute_set(struct proctal *p, int execute)
{
	p->allocate.execute = execute != 0;
}

void proctal_deallocate(struct proctal *p, void *address)
{
	proctal_implementation_deallocate(p, address);
}
