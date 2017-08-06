#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <darr.h>

#include "api/linux/mem.h"
#include "api/linux/proc.h"

static inline FILE *mem(struct proctal_linux *pl)
{
	if (pl->mem == NULL) {
		struct darr *path = proctal_linux_proc_path(pl->pid, "mem");
		pl->mem = fopen(darr_data(path), "r+");
		proctal_linux_proc_path_dispose(path);

		if (pl->mem == NULL) {
			proctal_error_set(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
			return NULL;
		}

		setvbuf(pl->mem, NULL, _IONBF, BUFSIZ);
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
		proctal_error_set(&pl->p, PROCTAL_ERROR_READ_FAILURE);
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
		proctal_error_set(&pl->p, PROCTAL_ERROR_WRITE_FAILURE);
		return 0;
	}

	// The way this is using the C library makes it seem like either
	// everything is written or nothing is. Might want to investigate
	// this.

	return size;
}

int proctal_linux_mem_swap(struct proctal_linux *pl, void *addr, char *dst, char *src, size_t size)
{
	int ret = 0;

	struct darr tmp;
	darr_init(&tmp, sizeof(char));

	if (!darr_resize(&tmp, size)) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_OUT_OF_MEMORY);
		goto exit1;
	}

	if (!proctal_linux_mem_read(pl, addr, darr_data(&tmp), size)) {
		goto exit1;
	}

	if (!proctal_linux_mem_write(pl, addr, src, size)) {
		goto exit1;
	}

	memcpy(dst, darr_data(&tmp), size);

	ret = 1;
exit1:
	darr_deinit(&tmp);
exit0:
	return ret;
}
