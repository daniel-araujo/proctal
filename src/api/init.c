#include "api/proctal.h"

void proctal_init(struct proctal *p)
{
	p->error = 0;

	p->address.region_mask = 0;
	p->address.size = 1;
	p->address.align = 1;
	p->address.read = 1;
	p->address.write = 0;
	p->address.execute = 0;

	p->region.mask = 0;
	p->region.read = 1;
	p->region.write = 0;
	p->region.execute = 0;

	p->watch.addr = NULL;
	p->watch.read = 1;
	p->watch.write = 1;
	p->watch.execute = 0;
}

void proctal_deinit(struct proctal *p)
{
}

proctal_t proctal_open(void)
{
	return proctal_impl_open();
}

void proctal_close(proctal_t p)
{
	return proctal_impl_close(p);
}
