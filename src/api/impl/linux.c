#include "api/proctal.h"
#include "api/linux/proctal.h"
#include "api/linux/mem.h"
#include "api/linux/ptrace.h"
#include "api/linux/address.h"
#include "api/linux/region.h"
#include "api/linux/watch.h"
#include "api/linux/allocate.h"
#include "api/linux/execute.h"

proctal_t proctal_impl_open(void)
{
	struct proctal_linux *pl = proctal_global_malloc(sizeof(*pl));

	if (pl == NULL) {
		return NULL;
	}

	proctal_linux_init(pl);

	return (proctal_t) pl;
}

void proctal_impl_close(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	if (pl == NULL) {
		return;
	}

	proctal_linux_deinit(pl);

	proctal_global_free(pl);
}

void proctal_impl_set_pid(proctal_t p, int pid)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_set_pid(pl, (pid_t) pid);
}

int proctal_impl_pid(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return (int) proctal_linux_pid(pl);
}

size_t proctal_impl_read(proctal_t p, void *addr, char *out, size_t size)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_mem_read(pl, addr, out, size);
}

size_t proctal_impl_write(proctal_t p, void *addr, const char *in, size_t size)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_mem_write(pl, addr, in, size);
}

int proctal_impl_freeze(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_ptrace_attach(pl);
}

int proctal_impl_unfreeze(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_ptrace_detach(pl);
}

void proctal_impl_scan_address_start(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_scan_address_start(pl);
}

void proctal_impl_scan_address_stop(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_scan_address_stop(pl);
}

int proctal_impl_scan_address(proctal_t p, void **addr)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_scan_address(pl, addr);
}

void proctal_impl_scan_region_start(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_scan_region_start(pl);
}

void proctal_impl_scan_region_stop(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_scan_region_stop(pl);
}

int proctal_impl_scan_region(proctal_t p, void **start, void **end)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_scan_region(pl, start, end);
}

int proctal_impl_watch_start(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_watch_start(pl);
}

void proctal_impl_watch_stop(proctal_t p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_watch_stop(pl);
}

int proctal_impl_watch(proctal_t p, void **addr)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_watch(pl, addr);
}

int proctal_impl_execute(proctal_t p, const char *byte_code, size_t byte_code_length)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_execute(pl, byte_code, byte_code_length);
}

void *proctal_impl_allocate(proctal_t p, size_t size, int perm)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_allocate(pl, size, perm);
}

void proctal_impl_deallocate(proctal_t p, void *addr)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_deallocate(pl, addr);
}
