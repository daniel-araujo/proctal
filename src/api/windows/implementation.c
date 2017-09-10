/*
 * An implementation that does nothing.
 */

#include "api/windows/proctal.h"
#include "api/windows/memory.h"

struct proctal *proctal_implementation_open(void)
{
	struct proctal *p = proctal_global_malloc(sizeof(*p));

	if (p == NULL) {
		return NULL;
	}

	proctal_init(p);

	return p;
}

void proctal_implementation_close(struct proctal *p)
{
	if (p == NULL) {
		return;
	}

	proctal_deinit(p);

	proctal_global_free(p);
}

void proctal_implementation_pid_set(struct proctal *p, int pid)
{
	struct proctal_windows *pw = (struct proctal_windows *) p;

	proctal_windows_pid_set(pw, pid);
}

int proctal_implementation_pid(struct proctal *p)
{
	struct proctal_windows *pw = (struct proctal_windows *) p;

	return proctal_windows_pid(pw);
}

size_t proctal_implementation_read(struct proctal *p, void *address, char *out, size_t size)
{
	struct proctal_windows *pw = (struct proctal_windows *) p;

	return proctal_windows_memory_read(pw, address, out, size);
}

size_t proctal_implementation_write(struct proctal *p, void *address, const char *in, size_t size)
{
	struct proctal_windows *pw = (struct proctal_windows *) p;

	return proctal_windows_memory_write(pw, address, in, size);
}

void proctal_implementation_freeze(struct proctal *p)
{
	struct proctal_windows *pw = (struct proctal_windows *) p;

	DebugActiveProcess(pw->process_id);
}

void proctal_implementation_unfreeze(struct proctal *p)
{
	struct proctal_windows *pw = (struct proctal_windows *) p;

	DebugActiveProcessStop(pw->process_id);
}

void proctal_implementation_scan_address_start(struct proctal *p)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}

void proctal_implementation_scan_address_stop(struct proctal *p)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}

int proctal_implementation_scan_address_next(struct proctal *p, void **address)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}

void proctal_implementation_scan_region_start(struct proctal *p)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}

void proctal_implementation_scan_region_stop(struct proctal *p)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}

int proctal_implementation_scan_region_next(struct proctal *p, void **start, void **end)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}

void proctal_implementation_watch_start(struct proctal *p)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}

void proctal_implementation_watch_stop(struct proctal *p)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}

int proctal_implementation_watch_next(struct proctal *p, void **address)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}

void proctal_implementation_execute(struct proctal *p, const char *bytecode, size_t bytecode_length)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}

void *proctal_implementation_allocate(struct proctal *p, size_t size)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
	return NULL;
}

void proctal_implementation_deallocate(struct proctal *p, void *address)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}
