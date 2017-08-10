#include "api/proctal.h"
#include "api/implementation.h"

void *proctal_watch_address(proctal_t p)
{
	return p->watch.addr;
}

void proctal_watch_address_set(proctal_t p, void *addr)
{
	p->watch.addr = addr;
}

int proctal_watch_read(proctal_t p)
{
	return p->watch.read;
}

void proctal_watch_read_set(proctal_t p, int r)
{
	p->watch.read = r != 0;
}

int proctal_watch_write(proctal_t p)
{
	return p->watch.write;
}

void proctal_watch_write_set(proctal_t p, int w)
{
	p->watch.write = w != 0;
}

int proctal_watch_execute(proctal_t p)
{
	return p->watch.execute;
}

void proctal_watch_execute_set(proctal_t p, int x)
{
	p->watch.execute = x != 0;
}

int proctal_watch_start(proctal_t p)
{
	return proctal_implementation_watch_start(p);
}

int proctal_watch(proctal_t p, void **addr)
{
	return proctal_implementation_watch(p, addr);
}

void proctal_watch_stop(proctal_t p)
{
	proctal_implementation_watch_stop(p);
}
