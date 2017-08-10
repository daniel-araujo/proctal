#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api/proctal.h"
#include "api/implementation.h"

void proctal_scan_address_start(proctal_t p)
{
	proctal_implementation_scan_address_start(p);
}

void proctal_scan_address_stop(proctal_t p)
{
	proctal_implementation_scan_address_stop(p);
}

size_t proctal_scan_address_size(proctal_t p)
{
	return p->address.size;
}

void proctal_scan_address_size_set(proctal_t p, size_t size)
{
	p->address.size = size > 0 ? size : 1;
}

size_t proctal_scan_address_align(proctal_t p)
{
	return p->address.align;
}

void proctal_scan_address_align_set(proctal_t p, size_t align)
{
	p->address.align = align > 0 ? align : 1;
}

long proctal_scan_address_region(proctal_t p)
{
	return p->address.region_mask;
}

void proctal_scan_address_region_set(proctal_t p, long mask)
{
	p->address.region_mask = mask;
}

int proctal_scan_address_read(proctal_t p)
{
	return p->address.read;
}

void proctal_scan_address_read_set(proctal_t p, int read)
{
	p->address.read = read != 0;
}

int proctal_scan_address_write(proctal_t p)
{
	return p->address.write;
}

void proctal_scan_address_write_set(proctal_t p, int write)
{
	p->address.write = write != 0;
}

int proctal_scan_address_execute(proctal_t p)
{
	return p->address.execute;
}

void proctal_scan_address_execute_set(proctal_t p, int execute)
{
	p->address.execute = execute != 0;
}

int proctal_scan_address(proctal_t p, void **addr)
{
	return proctal_implementation_scan_address(p, addr);
}
