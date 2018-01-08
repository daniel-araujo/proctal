#include "api/proctal.h"
#include "api/implementation.h"

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

	p->watch.address = NULL;
	p->watch.read = 1;
	p->watch.write = 1;
	p->watch.execute = 0;

	p->allocate.read = 1;
	p->allocate.write = 1;
	p->allocate.execute = 1;
}

void proctal_deinit(struct proctal *p)
{
}

struct proctal *proctal_open(void)
{
	return proctal_implementation_open();
}

void proctal_close(struct proctal *p)
{
	return proctal_implementation_close(p);
}
