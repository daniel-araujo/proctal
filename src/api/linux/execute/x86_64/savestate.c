#include "api/linux/proctal.h"
#include "api/linux/ptrace.h"

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

void *proctal_linux_execute_implementation_save_state(struct proctal_linux *pl, pid_t tid)
{
	struct state *s = proctal_malloc(&pl->p, sizeof(struct state));

	if (s == NULL) {
		return NULL;
	}

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
		proctal_free(&pl->p, s);
		return NULL;
	}

	return s;
}

int proctal_linux_execute_implementation_load_state(struct proctal_linux *pl, pid_t tid, void *state)
{
	struct state *s = state;

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
		proctal_free(&pl->p, s);
		return 0;
	}

	proctal_free(&pl->p, s);
	return 1;
}
