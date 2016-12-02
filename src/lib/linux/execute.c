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

	// TODO: Should generate byte code instead of hardcoding it, would be
	// easier to maintain.
	const char prologue[] = {
		// Escaping the red zone.
		0x81, 0xec, 0x80, 0x00, 0x00, 0x00,

		// Saving general purpose registers on the stack.
		0x50, 0x53, 0x51, 0x52, 0x55, 0x57, 0x56, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57,

		// TODO: Save other registers too.

		// TODO: Call code
	};
	const char epilogue[] = {
		// Restoring general purpose registers from the stack.
		0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5e, 0x5f, 0x5d, 0x5a, 0x59, 0x5b, 0x58,

		// Back into the red zone.
		0x81, 0xc4, 0x80, 0x00, 0x00, 0x00,

		// TODO: Return control back to the program.
	};

	size_t prologue_size = sizeof prologue / sizeof prologue[0];
	size_t epilogue_size = sizeof epilogue / sizeof epilogue[0];

	void *addr = proctal_linux_alloc(
		pl,
		prologue_size + epilogue_size + byte_code_length,
		PROCTAL_ALLOC_PERM_WRITE | PROCTAL_ALLOC_PERM_EXECUTE | PROCTAL_ALLOC_PERM_READ);

	if (addr == NULL) {
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	void *prologue_start_addr = addr;
	void *epilogue_start_addr = (char *) prologue_start_addr + prologue_size;
	void *code_start_addr = (char *) epilogue_start_addr + epilogue_size;

	if (!proctal_linux_mem_write(pl, prologue_start_addr, prologue, prologue_size)
		|| !proctal_linux_mem_write(pl, epilogue_start_addr, epilogue, epilogue_size)
		|| !proctal_linux_mem_write(pl, code_start_addr, byte_code, byte_code_length)) {
		proctal_linux_dealloc(pl, addr);
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	if (!proctal_linux_ptrace_set_instruction_address(pl, (char *) code_start_addr + 2)) {
		proctal_linux_dealloc(pl, addr);
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	if (!proctal_linux_ptrace_detach(pl)) {
		return 0;
	}

	return 1;
}
