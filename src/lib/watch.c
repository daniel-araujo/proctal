#include <proctal.h>

void proctal_watch_init(struct proctal *p, struct proctal_watch *pw)
{
	pw->addr = NULL;
	pw->started = 0;
	pw->read = 0;
	pw->write = 0;
	pw->execute = 0;
}

void proctal_watch_deinit(struct proctal *p, struct proctal_watch *pw)
{
}

proctal_watch proctal_watch_create(proctal p)
{
	return proctal_impl_watch_create(p);
}

void proctal_watch_destroy(proctal_watch pw)
{
	proctal_impl_watch_destroy(pw);
}

void *proctal_watch_addr(proctal_watch pw)
{
	return pw->addr;
}

void proctal_watch_set_addr(proctal_watch pw, void *addr)
{
	pw->addr = addr;
}

int proctal_watch_read(proctal_watch pw)
{
	return pw->read;
}

void proctal_watch_set_read(proctal_watch pw, int r)
{
	pw->read = r != 0;
}

int proctal_watch_write(proctal_watch pw)
{
	return pw->write;
}

void proctal_watch_set_write(proctal_watch pw, int w)
{
	pw->write = w != 0;
}

int proctal_watch_execute(proctal_watch pw)
{
	return pw->execute;
}

void proctal_watch_set_execute(proctal_watch pw, int x)
{
	pw->execute = x != 0;
}

int proctal_watch_next(proctal_watch pw, void **addr)
{
	return proctal_impl_watch_next(pw, addr);
}
