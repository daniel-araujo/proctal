#include <stdlib.h>

#include <proctal.h>

void *(*proctal_global_malloc)(size_t) = malloc;
void (*proctal_global_free)(void *) = free;

void proctal_global_set_malloc(void *(*malloc)(size_t))
{
	if (malloc == NULL) {
		proctal_global_malloc = malloc;
	}

	proctal_global_malloc = malloc;
}

void proctal_global_set_free(void (*free)(void *))
{
	if (free == NULL) {
		proctal_global_free = free;
	}

	proctal_global_free = free;
}

void proctal_init(struct proctal *p)
{
	p->malloc = proctal_global_malloc;
	p->free = proctal_global_free;
	p->error = 0;
}

void proctal_deinit(struct proctal *p)
{
}

proctal proctal_create(void)
{
	return proctal_impl_create();
}

void proctal_destroy(proctal p)
{
	return proctal_impl_destroy(p);
}

void proctal_set_pid(proctal p, int pid)
{
	proctal_impl_set_pid(p, pid);
}

void proctal_set_malloc(proctal p, void *(*malloc)(size_t))
{
	p->malloc = malloc;
}

void proctal_set_free(proctal p, void (*free)(void *))
{
	p->free = free;
}

int proctal_pid(proctal p)
{
	return proctal_impl_pid(p);
}

void *proctal_alloc(proctal p, size_t size)
{
	void *a = p->malloc(size);

	if (a == NULL) {
		proctal_set_error(p, PROCTAL_ERROR_OUT_OF_MEMORY);
	}

	return a;
}

void proctal_dealloc(proctal p, void *addr)
{
	return p->free(addr);
}

void *proctal_align_addr(void *addr, size_t align);
