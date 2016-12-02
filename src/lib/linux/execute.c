#include <linux/execute.h>
#include <linux/proc.h>
#include <linux/alloc.h>
#include <linux/mem.h>
#include <linux/ptrace.h>

struct syscall_save_state {
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

static inline int syscall_save_state(struct proctal_linux *pl, struct syscall_save_state *s)
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

static inline int syscall_load_state(struct proctal_linux *pl, struct syscall_save_state *s)
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

static inline int do_syscall(struct proctal_linux *pl, unsigned long long *ret)
{
	char code[] = { 0x0F, 0x05 };

	void *inject_addr = find_inject_addr(pl, sizeof code / sizeof code[0]);

	if (inject_addr == NULL) {
		proctal_set_error(&pl->p, PROCTAL_ERROR_INJECT_ADDR_NOT_FOUND);
		return 0;
	}

	if (!proctal_linux_mem_swap(pl, inject_addr, code, code, sizeof code / sizeof code[0])) {
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

	if (!proctal_linux_mem_swap(pl, inject_addr, code, code, sizeof code / sizeof code[0])) {
		return 0;
	}

	return 1;
}

int proctal_linux_execute_syscall(
	struct proctal_linux *pl,
	int num,
	unsigned long long *ret,
	unsigned long long one,
	unsigned long long two,
	unsigned long long three,
	unsigned long long four,
	unsigned long long five,
	unsigned long long six)
{
	struct syscall_save_state orig;

	if (!proctal_linux_ptrace_attach(pl)) {
		return 0;
	}

	if (!syscall_save_state(pl, &orig)) {
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	if (!set_syscall6(pl, num, one, two, three, four, five, six)
		|| !do_syscall(pl, ret)) {
		syscall_load_state(pl, &orig);
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	if (!syscall_load_state(pl, &orig)) {
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	if (!proctal_linux_ptrace_detach(pl)) {
		return 0;
	}

	return 1;
}

int proctal_linux_execute(struct proctal_linux *pl, const char *byte_code, size_t byte_code_length)
{
	if (!proctal_linux_ptrace_attach(pl)) {
		return 0;
	}

	void *addr = proctal_linux_alloc(
		pl,
		byte_code_length,
		PROCTAL_ALLOC_PERM_WRITE | PROCTAL_ALLOC_PERM_EXECUTE | PROCTAL_ALLOC_PERM_READ);

	if (addr == NULL) {
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	proctal_linux_mem_write(pl, addr, byte_code, byte_code_length);

	proctal_linux_ptrace_set_instruction_address(pl, addr);

	if (!proctal_linux_ptrace_detach(pl)) {
		return 0;
	}

	return 1;
}
