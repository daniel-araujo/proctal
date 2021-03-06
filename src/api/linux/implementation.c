/*
 * Linux implementation.
 */

#include "api/proctal.h"
#include "api/linux/proctal.h"
#include "api/linux/mem.h"
#include "api/linux/ptrace.h"
#include "api/linux/address.h"
#include "api/linux/region.h"
#include "api/linux/watch.h"
#include "api/linux/allocate.h"
#include "api/linux/execute.h"

struct proctal *proctal_implementation_open(void)
{
	struct proctal_linux *pl = proctal_global_malloc(sizeof(*pl));

	if (pl == NULL) {
		return NULL;
	}

	proctal_linux_init(pl);

	return (struct proctal *) pl;
}

void proctal_implementation_close(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	if (pl == NULL) {
		return;
	}

	proctal_linux_deinit(pl);

	proctal_global_free(pl);
}

void proctal_implementation_pid_set(struct proctal *p, int pid)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_pid_set(pl, (pid_t) pid);
}

int proctal_implementation_pid(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return (int) proctal_linux_pid(pl);
}

size_t proctal_implementation_read(struct proctal *p, void *address, void *out, size_t size)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_mem_read(pl, address, out, size);
}

size_t proctal_implementation_write(struct proctal *p, void *address, const void *in, size_t size)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_mem_write(pl, address, in, size);
}

void proctal_implementation_pause(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_ptrace_attach(pl);
}

void proctal_implementation_resume(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_ptrace_detach(pl);
}

void proctal_implementation_scan_address_start(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_scan_address_start(pl);
}

void proctal_implementation_scan_address_stop(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_scan_address_stop(pl);
}

int proctal_implementation_scan_address_next(struct proctal *p, void **address)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_scan_address_next(pl, address);
}

void proctal_implementation_scan_region_start(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_scan_region_start(pl);
}

void proctal_implementation_scan_region_stop(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_scan_region_stop(pl);
}

int proctal_implementation_scan_region_next(struct proctal *p, void **start, void **end)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_scan_region_next(pl, start, end);
}

void proctal_implementation_watch_start(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_watch_start(pl);
}

void proctal_implementation_watch_stop(struct proctal *p)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_watch_stop(pl);
}

int proctal_implementation_watch_next(struct proctal *p, void **address)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_watch_next(pl, address);
}

void proctal_implementation_execute(struct proctal *p, const char *bytecode, size_t bytecode_length)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_execute(pl, bytecode, bytecode_length);
}

void *proctal_implementation_allocate(struct proctal *p, size_t size)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	return proctal_linux_allocate(pl, size);
}

void proctal_implementation_deallocate(struct proctal *p, void *address)
{
	struct proctal_linux *pl = (struct proctal_linux *) p;

	proctal_linux_deallocate(pl, address);
}
