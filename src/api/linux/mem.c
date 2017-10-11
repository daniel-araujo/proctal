#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api/darr/darr.h"
#include "api/linux/mem.h"
#include "api/linux/proc.h"

static inline FILE *mem(struct proctal_linux *pl)
{
	if (pl->mem == NULL) {
		const struct proctal_darr *path = proctal_linux_proc_path(pl->pid, "mem");
		pl->mem = fopen(proctal_darr_data_const(path), "r+");
		proctal_linux_proc_path_dispose(path);

		if (pl->mem == NULL) {
			proctal_error_set(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
			return NULL;
		}

		setvbuf(pl->mem, NULL, _IONBF, BUFSIZ);
	}

	return pl->mem;
}

size_t proctal_linux_mem_read(struct proctal_linux *pl, void *address, void *out, size_t size)
{
	FILE *f = mem(pl);

	if (f == NULL) {
		return 0;
	}

	fseek(f, (long) address, SEEK_SET);

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

size_t proctal_linux_mem_write(struct proctal_linux *pl, void *address, const void *in, size_t size)
{
	FILE *f = mem(pl);

	if (f == NULL) {
		return 0;
	}

	fseek(f, (long) address, SEEK_SET);

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

int proctal_linux_mem_swap(struct proctal_linux *pl, void *address, void *dst, const void *src, size_t size)
{
	int ret = 0;

	struct proctal_darr tmp;
	proctal_darr_init(&tmp, sizeof(char));

	if (!proctal_darr_resize(&tmp, size)) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_OUT_OF_MEMORY);
		goto exit1;
	}

	if (!proctal_linux_mem_read(pl, address, proctal_darr_data(&tmp), size)) {
		goto exit1;
	}

	if (!proctal_linux_mem_write(pl, address, src, size)) {
		goto exit1;
	}

	memcpy(dst, proctal_darr_data(&tmp), size);

	ret = 1;
exit1:
	proctal_darr_deinit(&tmp);
exit0:
	return ret;
}

void *proctal_linux_mem_find_payload_location(struct proctal_linux *pl, size_t size)
{
	void *location = NULL;

	struct proctal_linux_proc_maps maps;

	if (!proctal_linux_proc_maps_open(&maps, pl->pid)) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		goto exit0;
	}

	struct proctal_linux_proc_maps_region *region;

	while ((region = proctal_linux_proc_maps_read(&maps))) {
		if (!region->execute) {
			continue;
		}

		size_t region_size = (size_t) ((char *) region->end - (char *) region->start);

		if (region_size >= size) {
			location = region->start;
			break;
		}
	}

exit0:
	return location;
}
