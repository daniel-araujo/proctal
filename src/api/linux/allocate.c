#include <string.h>
#include <sys/mman.h>

#include "api/linux/allocate.h"
#include "api/linux/proc.h"
#include "api/linux/mem.h"
#include "api/linux/execute.h"

struct mem_header {
	size_t size;
};

static inline int make_prot(struct proctal_linux *pl)
{
	int prot = 0;

	if (pl->p.allocate.read) {
		prot |= PROT_READ;
	}

	if (pl->p.allocate.write) {
		prot |= PROT_WRITE;
	}

	if (pl->p.allocate.execute) {
		prot |= PROT_EXEC;
	}

	if (prot == 0) {
		prot = PROT_NONE;
	}

	return prot;
}

static inline void *read_header(struct proctal_linux *pl, struct mem_header *header, void *address)
{
	void *memory_location = (char *) address - sizeof(header);

	if (!proctal_linux_mem_read(pl, memory_location, (char *) header, sizeof(header))) {
		return NULL;
	}

	return memory_location;
}

static inline void *write_header(struct proctal_linux *pl, struct mem_header *header, void *memory_location)
{
	if (!proctal_linux_mem_write(pl, memory_location, (char *) header, sizeof(header))) {
		return NULL;
	}

	return (char *) memory_location + sizeof(header);
}

void *proctal_linux_allocate(struct proctal_linux *pl, size_t size)
{
	struct mem_header header;
	header.size = size + sizeof(header);

	void *ret = proctal_linux_execute_syscall_mmap(
		pl,
		NULL,
		header.size,
		make_prot(pl),
		0x22, // MAP_PRIVATE | MAP_ANONYMOUS
		-1,
		0);

	if (proctal_error(&pl->p)) {
		return NULL;
	}

	// TODO: Detect error codes from system call return values.

	return write_header(pl, &header, ret);
}

void proctal_linux_deallocate(struct proctal_linux *pl, void *address)
{
	struct mem_header header;

	void *memory_location = read_header(pl, &header, address);

	int ret = proctal_linux_execute_syscall_munmap(pl, memory_location, header.size);

	if (proctal_error(&pl->p)) {
		return;
	}

	if (ret != 0) {
		// TODO: Detect error codes from system call return values.
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNKNOWN);
	}
}
