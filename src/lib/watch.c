#include "lib/proctal.h"

void *proctal_watch_address(proctal_t p)
{
	return p->watch.addr;
}

void proctal_watch_set_address(proctal_t p, void *addr)
{
	p->watch.addr = addr;
}

int proctal_watch_read(proctal_t p)
{
	return p->watch.read;
}

void proctal_watch_set_read(proctal_t p, int r)
{
	p->watch.read = r != 0;
}

int proctal_watch_write(proctal_t p)
{
	return p->watch.write;
}

void proctal_watch_set_write(proctal_t p, int w)
{
	p->watch.write = w != 0;
}

int proctal_watch_execute(proctal_t p)
{
	return p->watch.execute;
}

void proctal_watch_set_execute(proctal_t p, int x)
{
	p->watch.execute = x != 0;
}

int proctal_watch(proctal_t p, void **addr)
{
	return proctal_impl_watch(p, addr);
}
