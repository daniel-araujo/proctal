#include "api/linux/proc.h"
#include "api/linux/allocate.h"
#include "api/linux/mem.h"
#include "api/linux/ptrace.h"
#include "magic/magic.h"

/*
 * Architecture specific no op code.
 */
extern const char proctal_linux_execute_implementation_no_op_code[];

/*
 * Size of no op code.
 */
extern const size_t proctal_linux_execute_implementation_no_op_code_size;

/*
 * Architecture specific code that dispatches a trap signal.
 */
extern const char proctal_linux_execute_implementation_trap_code[];

/*
 * Size of architecture specific code that dispatches a trap signal.
 */
extern const size_t proctal_linux_execute_implementation_trap_code_size;

#define RED_ZONE_SIZE 128

struct state {
	unsigned long long rax;
	unsigned long long rbx;
	unsigned long long rcx;
	unsigned long long rdx;
	unsigned long long rsi;
	unsigned long long rdi;
	unsigned long long rbp;
	unsigned long long rsp;
	unsigned long long rip;
	unsigned long long rflags;
	unsigned long long r8;
	unsigned long long r9;
	unsigned long long r10;
	unsigned long long r11;
	unsigned long long r12;
	unsigned long long r13;
	unsigned long long r14;
	unsigned long long r15;

	// TODO: Save remaining registers.
};

static inline int save_state(struct proctal_linux *pl, pid_t tid, struct state *s)
{
	if (!proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RAX, &s->rax)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBX, &s->rbx)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RCX, &s->rcx)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDX, &s->rdx)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSI, &s->rsi)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDI, &s->rdi)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBP, &s->rbp)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSP, &s->rsp)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RIP, &s->rip)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RFLAGS, &s->rflags)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R8, &s->r8)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R9, &s->r9)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R10, &s->r10)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R11, &s->r11)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R12, &s->r12)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R13, &s->r13)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R14, &s->r14)
		|| !proctal_linux_ptrace_register(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R15, &s->r15)) {
		return 0;
	}

	return 1;
}

static inline int load_state(struct proctal_linux *pl, pid_t tid, struct state *s)
{
	if (!proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RAX, &s->rax)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBX, &s->rbx)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RCX, &s->rcx)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDX, &s->rdx)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSI, &s->rsi)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDI, &s->rdi)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBP, &s->rbp)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSP, &s->rsp)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RIP, &s->rip)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RFLAGS, &s->rflags)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R8, &s->r8)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R9, &s->r9)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R10, &s->r10)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R11, &s->r11)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R12, &s->r12)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R13, &s->r13)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R14, &s->r14)
		|| !proctal_linux_ptrace_register_set(pl, tid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R15, &s->r15)) {
		return 0;
	}

	return 1;
}

int proctal_linux_execute_implementation(
	struct proctal_linux *pl,
	const char *bytecode,
	size_t bytecode_length)
{
	int ret = 0;

	struct state savestate;

	if (!proctal_linux_ptrace_attach(pl)) {
		goto exit0;
	}

	void *payload_location = proctal_linux_allocate(
		pl,
		proctal_linux_execute_implementation_no_op_code_size + bytecode_length + proctal_linux_execute_implementation_trap_code_size,
		PROCTAL_ALLOCATE_PERMISSION_WRITE | PROCTAL_ALLOCATE_PERMISSION_EXECUTE | PROCTAL_ALLOCATE_PERMISSION_READ);

	if (payload_location == NULL) {
		proctal_linux_ptrace_detach(pl);
		return 0;
	}

	void *no_op_code_location = payload_location;
	void *bytecode_location = (char *) no_op_code_location + proctal_linux_execute_implementation_no_op_code_size;
	void *trap_code_location = (char *) bytecode_location + bytecode_length;

	void *landing_zone = (char *) no_op_code_location + (proctal_linux_execute_implementation_no_op_code_size / 2);

	if (!save_state(pl, pl->pid, &savestate)) {
		goto exit1;
	}

	unsigned long long stack_pointer = savestate.rsp - RED_ZONE_SIZE;
	unsigned long long base_pointer = stack_pointer;

	// Create new stack frame.
	if (!proctal_linux_ptrace_register_set(pl, pl->pid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSP, &stack_pointer)
		|| !proctal_linux_ptrace_register_set(pl, pl->pid, PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBP, &base_pointer)) {
		goto exit3;
	}

	// Place payload.
	if (!proctal_linux_mem_write(pl, no_op_code_location, proctal_linux_execute_implementation_no_op_code, proctal_linux_execute_implementation_no_op_code_size)
		|| !proctal_linux_mem_write(pl, bytecode_location, bytecode, bytecode_length)
		|| !proctal_linux_mem_write(pl, trap_code_location, proctal_linux_execute_implementation_trap_code, proctal_linux_execute_implementation_trap_code_size)) {
		goto exit3;
	}

	// Execute payload. Will block until the trap signal is received.
	if (!proctal_linux_ptrace_instruction_pointer_set(pl, pl->pid, landing_zone)
		|| !proctal_linux_ptrace_cont(pl, pl->pid)
		|| !proctal_linux_ptrace_wait_trap(pl, pl->pid)) {
		goto exit3;
	}

	ret = 1;
exit3:
	if (!load_state(pl, pl->pid, &savestate)) {
		ret = 0;
	}
exit2:
	proctal_linux_deallocate(pl, payload_location);
exit1:
	if (!proctal_linux_ptrace_detach(pl)) {
		ret = 0;
	}
exit0:
	return ret;
}
