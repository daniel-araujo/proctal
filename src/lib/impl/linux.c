#include "lib/proctal.h"
#include "lib/linux/proctal.h"
#include "lib/linux/mem.h"
#include "lib/linux/ptrace.h"
#include "lib/linux/address.h"
#include "lib/linux/region.h"
#include "lib/linux/watch.h"
#include "lib/linux/alloc.h"
#include "lib/linux/execute.h"

proctal proctal_impl_create(void)
{
	struct proctal_linux *pl = proctal_global_malloc(sizeof *pl);

	if (pl == NULL) {
		return NULL;
	}

	proctal_linux_init(pl);

	return (proctal) pl;
}

void proctal_impl_destroy(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	if (pl == NULL) {
		return;
	}

	proctal_linux_deinit(pl);

	proctal_global_free(pl);
}

void proctal_impl_set_pid(proctal p, int pid)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_set_pid(pl, (pid_t) pid);
}

int proctal_impl_pid(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return (int) proctal_linux_pid(pl);
}

size_t proctal_impl_read(proctal p, void *addr, char *out, size_t size)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_mem_read(pl, addr, out, size);
}

size_t proctal_impl_write(proctal p, void *addr, const char *in, size_t size)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_mem_write(pl, addr, in, size);
}

int proctal_impl_freeze(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_ptrace_attach(pl);
}

int proctal_impl_unfreeze(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_ptrace_detach(pl);
}

void proctal_impl_address_new(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_address_new(pl);
}

int proctal_impl_address(proctal p, void **addr)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_address(pl, addr);
}

void proctal_impl_region_new(proctal p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_region_new(pl);
}

int proctal_impl_region(proctal p, void **start, void **end)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_region(pl, start, end);
}

int proctal_impl_watch(proctal p, void **addr)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_watch(pl, addr);
}

int proctal_impl_execute(proctal p, const char *byte_code, size_t byte_code_length)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_execute(pl, byte_code, byte_code_length);
}

void *proctal_impl_alloc(proctal p, size_t size, int perm)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_alloc(pl, size, perm);
}

void proctal_impl_dealloc(proctal p, void *addr)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_dealloc(pl, addr);
}
