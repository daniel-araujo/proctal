#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "lib/proctal.h"

void proctal_address_new(proctal_t p)
{
	proctal_impl_address_new(p);
}

size_t proctal_address_size(proctal_t p)
{
	return p->address.size;
}

void proctal_address_set_size(proctal_t p, size_t size)
{
	p->address.size = size > 0 ? size : 1;
}

size_t proctal_address_align(proctal_t p)
{
	return p->address.align;
}

void proctal_address_set_align(proctal_t p, size_t align)
{
	p->address.align = align > 0 ? align : 1;
}

long proctal_address_region(proctal_t p)
{
	return p->address.region_mask;
}

void proctal_address_set_region(proctal_t p, long mask)
{
	p->address.region_mask = mask;
}

int proctal_address_read(proctal_t p)
{
	return p->address.read;
}

void proctal_address_set_read(proctal_t p, int read)
{
	p->address.read = read != 0;
}

int proctal_address_write(proctal_t p)
{
	return p->address.write;
}

void proctal_address_set_write(proctal_t p, int write)
{
	p->address.write = write != 0;
}

int proctal_address_execute(proctal_t p)
{
	return p->address.execute;
}

void proctal_address_set_execute(proctal_t p, int execute)
{
	p->address.execute = execute != 0;
}

int proctal_address(proctal_t p, void **addr)
{
	return proctal_impl_address(p, addr);
}
