#include "api/proctal.h"
#include "api/implementation.h"

void *proctal_watch_address(struct proctal *p)
{
	return p->watch.addr;
}

void proctal_watch_address_set(struct proctal *p, void *addr)
{
	p->watch.addr = addr;
}

int proctal_watch_read(struct proctal *p)
{
	return p->watch.read;
}

void proctal_watch_read_set(struct proctal *p, int r)
{
	p->watch.read = r != 0;
}

int proctal_watch_write(struct proctal *p)
{
	return p->watch.write;
}

void proctal_watch_write_set(struct proctal *p, int w)
{
	p->watch.write = w != 0;
}

int proctal_watch_execute(struct proctal *p)
{
	return p->watch.execute;
}

void proctal_watch_execute_set(struct proctal *p, int x)
{
	p->watch.execute = x != 0;
}

void proctal_watch_start(struct proctal *p)
{
	proctal_implementation_watch_start(p);
}

void proctal_watch_stop(struct proctal *p)
{
	proctal_implementation_watch_stop(p);
}

int proctal_watch_next(struct proctal *p, void **addr)
{
	return proctal_implementation_watch_next(p, addr);
}
