#include <stdlib.h>
#include <stdio.h>

#include <linux/mem.h>
#include <linux/proc.h>

static inline FILE *mem(struct proctal_linux *pl)
{
	if (pl->mem == NULL) {
		pl->mem = fopen(proctal_linux_proc_path(pl->pid, "mem"), "r+");
	}

	if (pl->mem == NULL) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
	}

	return pl->mem;
}

size_t proctal_linux_mem_read(struct proctal_linux *pl, void *addr, char *out, size_t size)
{
	FILE *f = mem(pl);

	if (f == NULL) {
		return 0;
	}

	fseek(f, (long) addr, SEEK_SET);

	long i = fread(out, size, 1, f);

	if (i != 1) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_READ_FAILURE);
		return 0;
	}

	// The way this is using the C library makes it seem like either
	// everything is read or nothing is. Might want to investigate
	// this.

	return size;
}

size_t proctal_linux_mem_write(struct proctal_linux *pl, void *addr, const char *in, size_t size)
{
	FILE *f = mem(pl);

	if (f == NULL) {
		return 0;
	}

	fseek(f, (long) addr, SEEK_SET);

	long i = fwrite(in, size, 1, f);

	if (i != 1) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_WRITE_FAILURE);
		return 0;
	}

	// The way this is using the C library makes it seem like either
	// everything is written or nothing is. Might want to investigate
	// this.

	return size;
}
