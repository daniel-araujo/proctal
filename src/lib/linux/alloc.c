#include <string.h>
#include <sys/mman.h>

#include <linux/alloc.h>
#include <linux/proc.h>
#include <linux/ptrace.h>
#include <linux/mem.h>

struct state {
	void *addr; // Instruction pointer.
	unsigned long long eflags; // Flags.
	unsigned long long rdi; // First argument.
	unsigned long long rsi; // Second argument.
	unsigned long long rdx; // Third argument.
	unsigned long long r10; // Fourth argument.
	unsigned long long r8; // Fifth argument.
	unsigned long long r9; // Sixth argument.
	unsigned long long rax; // Return value.

	unsigned long long rcx; // May be modifed.
	unsigned long long r11; // May be modifed.
};

struct mem_header {
	size_t size;
};

static inline int make_prot(int permissions)
{
	int prot = 0;

	if (permissions & PROCTAL_ALLOC_PERM_READ) {
		prot |= PROT_READ;
	}

	if (permissions & PROCTAL_ALLOC_PERM_WRITE) {
		prot |= PROT_WRITE;
	}

	if (permissions & PROCTAL_ALLOC_PERM_EXECUTE) {
		prot |= PROT_EXEC;
	}

	if (prot == 0) {
		prot = PROT_NONE;
	}

	return prot;
}

static inline int save_state(struct proctal_linux *pl, struct state *s)
{
	if (!proctal_linux_ptrace_get_instruction_address(pl, &s->addr)
		|| !proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RDI, &s->rdi)
		|| !proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RSI, &s->rsi)
		|| !proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RDX, &s->rdx)
		|| !proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R10, &s->r10)
		|| !proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R8, &s->r8)
		|| !proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R9, &s->r9)
		|| !proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RAX, &s->rax)
		|| !proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RCX, &s->rcx)
		|| !proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R11, &s->r11)) {
		return 0;
	}

	return 1;
}

static inline int load_state(struct proctal_linux *pl, struct state *s)
{
	if (!proctal_linux_ptrace_set_instruction_address(pl, s->addr)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RDI, s->rdi)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RSI, s->rsi)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RDX, s->rdx)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R10, s->r10)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R8, s->r8)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R9, s->r9)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RAX, s->rax)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RCX, s->rcx)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R11, s->r11)) {
		return 0;
	}

	return 1;
}

static inline int set_syscall6(
	struct proctal_linux *pl, 
	int num,
	unsigned long long one,
	unsigned long long two,
	unsigned long long three,
	unsigned long long four,
	unsigned long long five,
	unsigned long long six)
{
	if (!proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RAX, num)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RDI, one)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RSI, two)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RDX, three)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R10, four)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R8, five)
		|| !proctal_linux_ptrace_set_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_R9, six)) {
		return 0;
	}

	return 1;
}

static inline void *find_inject_addr(struct proctal_linux *pl, size_t size)
{
	FILE *maps = fopen(proctal_linux_proc_path(pl->pid, "maps"), "r");

	if (maps == NULL) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_PERMISSION_DENIED);
		return NULL;
	}

	struct proctal_linux_mem_region region;

	void *addr = NULL;

	while (proctal_linux_read_mem_region(&region, maps) == 0) {
		if (region.execute) {
			size_t region_size = (size_t) ((char *) region.end_addr - (char *) region.start_addr);

			if (region_size >= size) {
				addr = region.start_addr;
				break;
			}
		}
	}

	fclose(maps);

	return addr;
}

static inline int swap_memory(struct proctal_linux *pl, void *addr, char *dst, char *src, size_t size)
{
	char t[size];

	if (!proctal_linux_mem_read(pl, addr, t, size)) {
		return 0;
	}

	if (!proctal_linux_mem_write(pl, addr, src, size)) {
		return 0;
	}

	memcpy(dst, t, size);

	return 1;
}

static inline int do_syscall(struct proctal_linux *pl, unsigned long long *ret)
{
	char code[] = { 0x0F, 0x05 };

	void *inject_addr = find_inject_addr(pl, sizeof code / sizeof code[0]);

	if (inject_addr == NULL) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_INJECT_ADDR_NOT_FOUND);
		return 0;
	}

	if (!swap_memory(pl, inject_addr, code, code, sizeof code / sizeof code[0])) {
		return 0;
	}

	if (!proctal_linux_ptrace_set_instruction_address(pl, inject_addr)) {
		return 0;
	}

	if (!proctal_linux_ptrace_step(pl)) {
		return 0;
	}

	if (!proctal_linux_ptrace_get_x86_reg(pl, PROCTAL_LINUX_PTRACE_X86_REG_RAX, ret)) {
		return 0;
	}

	if (!swap_memory(pl, inject_addr, code, code, sizeof code / sizeof code[0])) {
		return 0;
	}

	return 1;
}

static inline void *read_header(struct proctal_linux *pl, struct mem_header *header, void *addr)
{
	void *alloc_addr = (char *) addr - sizeof header;

	if (!proctal_linux_mem_read(pl, alloc_addr, (char *) header, sizeof header)) {
		return NULL;
	}

	return alloc_addr;
}

static inline void *write_header(struct proctal_linux *pl, struct mem_header *header, void *alloc_addr)
{
	if (!proctal_linux_mem_write(pl, alloc_addr, (char *) header, sizeof header)) {
		return NULL;
	}

	return (char *) alloc_addr + sizeof header;
}

void *proctal_linux_alloc(struct proctal_linux *pl, size_t size, int permissions)
{
	struct state orig;

	int prot = make_prot(permissions);
	int flags = 0x22; // MAP_PRIVATE | MAP_ANONYMOUS

	if (!proctal_linux_ptrace_attach(pl)) {
		return NULL;
	}

	if (!save_state(pl, &orig)) {
		proctal_linux_ptrace_detach(pl);
		return NULL;
	}

	void *alloc_addr = NULL;

	struct mem_header header;
	header.size = size + sizeof header;

	// mmap x86-64 system call.
	if (!set_syscall6(pl, 9, 0, header.size, prot, flags, -1, 0)
		|| !do_syscall(pl, (unsigned long long *) &alloc_addr)) {
		load_state(pl, &orig);
		proctal_linux_ptrace_detach(pl);
		return NULL;
	}

	void *addr = write_header(pl, &header, alloc_addr);

	if (addr == NULL) {
		return NULL;
	}

	if (!load_state(pl, &orig)) {
		proctal_linux_ptrace_detach(pl);
		return NULL;
	}

	if (!proctal_linux_ptrace_detach(pl)) {
		return NULL;
	}

	return addr;
}

void proctal_linux_dealloc(struct proctal_linux *pl, void *addr)
{
	struct state orig;

	if (!proctal_linux_ptrace_attach(pl)) {
		return;
	}

	struct mem_header header;
	void *alloc_addr = read_header(pl, &header, addr);

	if (alloc_addr == NULL) {
		proctal_linux_ptrace_detach(pl);
		return;
	}

	if (!save_state(pl, &orig)) {
		proctal_linux_ptrace_detach(pl);
		return;
	}

	unsigned long long ret;

	// munmap x86-64 system call.
	if (!set_syscall6(pl, 11, (unsigned long long) alloc_addr, header.size, 0, 0, 0, 0)
		|| !do_syscall(pl, &ret)) {
		load_state(pl, &orig);
		proctal_linux_ptrace_detach(pl);
		return;
	}

	if (!load_state(pl, &orig)) {
		proctal_linux_ptrace_detach(pl);
		return;
	}

	if (ret != 0) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_UNKNOWN);
		proctal_linux_ptrace_detach(pl);
		return;
	}

	proctal_linux_ptrace_detach(pl);
}
