#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <proctal.h>

static inline int has_started(struct proctal_addr_iter *iter)
{
	return iter->started;
}

static inline int has_finished(struct proctal_addr_iter *iter)
{
	return iter->started && iter->curr_addr == NULL;
}

void proctal_addr_iter_init(struct proctal *p, struct proctal_addr_iter *iter)
{
	iter->curr_addr = NULL;
	iter->region_mask = PROCTAL_ADDR_REGION_HEAP | PROCTAL_ADDR_REGION_STACK;
	iter->size = 1;
	iter->align = 1;
	iter->started = 0;
}

void proctal_addr_iter_deinit(struct proctal *p, struct proctal_addr_iter *iter)
{
	if (iter == NULL) {
		return;
	}
}

proctal_addr_iter proctal_addr_iter_create(proctal p)
{
	return proctal_impl_addr_iter_create(p);
}

void proctal_addr_iter_destroy(proctal_addr_iter iter)
{
	proctal_impl_addr_iter_destroy(iter);
}

size_t proctal_addr_iter_size(proctal_addr_iter iter)
{
	return iter->size;
}

void proctal_addr_iter_set_size(proctal_addr_iter iter, size_t size)
{
	iter->size = size > 0 ? size : 1;
}

size_t proctal_addr_iter_align(proctal_addr_iter iter)
{
	return iter->align;
}

void proctal_addr_iter_set_align(proctal_addr_iter iter, size_t align)
{
	iter->align = align > 0 ? align : 1;
}

long proctal_addr_iter_region(proctal_addr_iter iter)
{
	return iter->region_mask;
}

void proctal_addr_iter_set_region(proctal_addr_iter iter, long mask)
{
	iter->region_mask = mask;
}

int proctal_addr_iter_next(proctal_addr_iter iter, void **addr)
{
	if (!has_started(iter)) {
		iter->started = 1;

		if (!proctal_impl_addr_iter_first(iter)) {
			return 0;
		}

		*addr = iter->curr_addr;
		return 1;
	} else if (has_finished(iter)) {
		return 0;
	}

	if (proctal_impl_addr_iter_next(iter)) {
		*addr = iter->curr_addr;
		return 1;
	} else {
		return 0;
	}
}
