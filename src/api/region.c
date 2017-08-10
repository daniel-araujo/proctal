#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api/proctal.h"
#include "api/implementation.h"

void proctal_scan_region_start(proctal_t p)
{
	proctal_implementation_scan_region_start(p);
}

void proctal_scan_region_stop(proctal_t p)
{
	proctal_implementation_scan_region_stop(p);
}

long proctal_scan_region_mask(proctal_t p)
{
	return p->region.mask;
}

void proctal_scan_region_mask_set(proctal_t p, long mask)
{
	p->region.mask = mask;
}

int proctal_scan_region_read(proctal_t p)
{
	return p->region.read;
}

void proctal_scan_region_read_set(proctal_t p, int read)
{
	p->region.read = read != 0;
}

int proctal_scan_region_write(proctal_t p)
{
	return p->region.write;
}

void proctal_scan_region_write_set(proctal_t p, int write)
{
	p->region.write = write != 0;
}

int proctal_scan_region_execute(proctal_t p)
{
	return p->region.execute;
}

void proctal_scan_region_execute_set(proctal_t p, int execute)
{
	p->region.execute = execute != 0;
}

int proctal_scan_region(proctal_t p, void **start, void **end)
{
	return proctal_implementation_scan_region(p, start, end);
}
