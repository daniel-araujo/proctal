#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "lib/proctal.h"

void proctal_region_new(proctal_t p)
{
	proctal_impl_region_new(p);
}

long proctal_region_mask(proctal_t p)
{
	return p->region.mask;
}

void proctal_region_set_mask(proctal_t p, long mask)
{
	p->region.mask = mask;
}

int proctal_region_read(proctal_t p)
{
	return p->region.read;
}

void proctal_region_set_read(proctal_t p, int read)
{
	p->region.read = read != 0;
}

int proctal_region_write(proctal_t p)
{
	return p->region.write;
}

void proctal_region_set_write(proctal_t p, int write)
{
	p->region.write = write != 0;
}

int proctal_region_execute(proctal_t p)
{
	return p->region.execute;
}

void proctal_region_set_execute(proctal_t p, int execute)
{
	p->region.execute = execute != 0;
}

int proctal_region(proctal_t p, void **start, void **end)
{
	return proctal_impl_region(p, start, end);
}
