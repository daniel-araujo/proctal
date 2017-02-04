#include "lib/proctal.h"

void *proctal_watch_address(proctal p)
{
	return p->watch.addr;
}

void proctal_watch_set_address(proctal p, void *addr)
{
	p->watch.addr = addr;
}

int proctal_watch_read(proctal p)
{
	return p->watch.read;
}

void proctal_watch_set_read(proctal p, int r)
{
	p->watch.read = r != 0;
}

int proctal_watch_write(proctal p)
{
	return p->watch.write;
}

void proctal_watch_set_write(proctal p, int w)
{
	p->watch.write = w != 0;
}

int proctal_watch_execute(proctal p)
{
	return p->watch.execute;
}

void proctal_watch_set_execute(proctal p, int x)
{
	p->watch.execute = x != 0;
}

int proctal_watch(proctal p, void **addr)
{
	return proctal_impl_watch(p, addr);
}
