#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api/proctal.h"
#include "api/implementation.h"

void proctal_scan_region_start(struct proctal *p)
{
	proctal_implementation_scan_region_start(p);
}

void proctal_scan_region_stop(struct proctal *p)
{
	proctal_implementation_scan_region_stop(p);
}

long proctal_scan_region_mask(struct proctal *p)
{
	return p->region.mask;
}

void proctal_scan_region_mask_set(struct proctal *p, long mask)
{
	p->region.mask = mask;
}

int proctal_scan_region_read(struct proctal *p)
{
	return p->region.read;
}

void proctal_scan_region_read_set(struct proctal *p, int read)
{
	p->region.read = read != 0;
}

int proctal_scan_region_write(struct proctal *p)
{
	return p->region.write;
}

void proctal_scan_region_write_set(struct proctal *p, int write)
{
	p->region.write = write != 0;
}

int proctal_scan_region_execute(struct proctal *p)
{
	return p->region.execute;
}

void proctal_scan_region_execute_set(struct proctal *p, int execute)
{
	p->region.execute = execute != 0;
}

int proctal_scan_region_next(struct proctal *p, void **start, void **end)
{
	return proctal_implementation_scan_region_next(p, start, end);
}
