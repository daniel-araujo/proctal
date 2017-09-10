#include "api/proctal.h"
#include "api/implementation.h"

void *proctal_watch_address(struct proctal *p)
{
	return p->watch.address;
}

void proctal_watch_address_set(struct proctal *p, void *address)
{
	p->watch.address = address;
}

int proctal_watch_read(struct proctal *p)
{
	return p->watch.read;
}

void proctal_watch_read_set(struct proctal *p, int read)
{
	p->watch.read = read != 0;
}

int proctal_watch_write(struct proctal *p)
{
	return p->watch.write;
}

void proctal_watch_write_set(struct proctal *p, int write)
{
	p->watch.write = write != 0;
}

int proctal_watch_execute(struct proctal *p)
{
	return p->watch.execute;
}

void proctal_watch_execute_set(struct proctal *p, int execute)
{
	p->watch.execute = execute != 0;
}

void proctal_watch_start(struct proctal *p)
{
	proctal_implementation_watch_start(p);
}

void proctal_watch_stop(struct proctal *p)
{
	proctal_implementation_watch_stop(p);
}

int proctal_watch_next(struct proctal *p, void **address)
{
	return proctal_implementation_watch_next(p, address);
}
