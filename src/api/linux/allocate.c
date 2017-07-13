#include <string.h>
#include <sys/mman.h>

#include "api/linux/allocate.h"
#include "api/linux/proc.h"
#include "api/linux/mem.h"
#include "api/linux/execute.h"

struct mem_header {
	size_t size;
};

static inline int make_prot(int permissions)
{
	int prot = 0;

	if (permissions & PROCTAL_ALLOCATE_PERM_READ) {
		prot |= PROT_READ;
	}

	if (permissions & PROCTAL_ALLOCATE_PERM_WRITE) {
		prot |= PROT_WRITE;
	}

	if (permissions & PROCTAL_ALLOCATE_PERM_EXECUTE) {
		prot |= PROT_EXEC;
	}

	if (prot == 0) {
		prot = PROT_NONE;
	}

	return prot;
}

static inline void *read_header(struct proctal_linux *pl, struct mem_header *header, void *addr)
{
	void *alloc_addr = (char *) addr - sizeof(header);

	if (!proctal_linux_mem_read(pl, alloc_addr, (char *) header, sizeof(header))) {
		return NULL;
	}

	return alloc_addr;
}

static inline void *write_header(struct proctal_linux *pl, struct mem_header *header, void *alloc_addr)
{
	if (!proctal_linux_mem_write(pl, alloc_addr, (char *) header, sizeof(header))) {
		return NULL;
	}

	return (char *) alloc_addr + sizeof(header);
}

void *proctal_linux_allocate(struct proctal_linux *pl, size_t size, int permissions)
{
	int prot = make_prot(permissions);
	int flags = 0x22; // MAP_PRIVATE | MAP_ANONYMOUS

	struct mem_header header;
	header.size = size + sizeof(header);

	void *alloc_addr = NULL;

	// mmap x86-64 system call.
	if (!proctal_linux_execute_syscall(pl, 9, (unsigned long long *) &alloc_addr, 0, header.size, prot, flags, -1, 0)) {
		return NULL;
	}

	void *addr = write_header(pl, &header, alloc_addr);

	return addr;
}

void proctal_linux_deallocate(struct proctal_linux *pl, void *addr)
{
	struct mem_header header;
	void *alloc_addr = read_header(pl, &header, addr);

	unsigned long long ret;

	// munmap x86-64 system call.
	if (!proctal_linux_execute_syscall(pl, 11, &ret, (unsigned long long) alloc_addr, header.size, 0, 0, 0, 0)) {
		return;
	}

	if (ret != 0) {
		proctal_error_set(&pl->p, PROCTAL_ERROR_UNKNOWN);
	}
}
