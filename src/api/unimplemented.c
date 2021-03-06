/*
 * An implementation that does nothing.
 */

#include "api/proctal.h"

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
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}

int proctal_implementation_pid(struct proctal *p)
{
	return 0;
}

size_t proctal_implementation_read(struct proctal *p, void *address, void *out, size_t size)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}

size_t proctal_implementation_write(struct proctal *p, void *address, const void *in, size_t size)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
	return 0;
}

void proctal_implementation_pause(struct proctal *p)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
}

void proctal_implementation_resume(struct proctal *p)
{
	proctal_error_set(p, PROCTAL_ERROR_UNSUPPORTED);
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

void proctal_implementation_execute(struct proctal *p, const void *bytecode, size_t bytecode_length)
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
