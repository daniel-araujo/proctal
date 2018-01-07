#include <sys/user.h>

#include "api/linux/proctal.h"
#include "api/linux/ptrace/internal.h"
#include "magic/magic.h"

int proctal_linux_ptrace_implementation_register_user_offset(int regid)
{
#define OFFSET_INTO_REGS(REG) \
	offsetof(struct user, regs) + offsetof(struct user_regs_struct, REG)

	switch (regid) {
	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR0:
	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR1:
	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR2:
	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR3:
	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR4:
	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR5:
	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR6:
	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR7:
		// Taking advantage that they're sequential numbers. That
		// allows us to subtract from the first one, giving us an index
		// into the debug registers array member.
		regid -= PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR0;

		return offsetof(struct user, u_debugreg)
			+ sizeof(((struct user *) 0)->u_debugreg[0]) * regid;

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RAX:
		return OFFSET_INTO_REGS(rax);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBX:
		return OFFSET_INTO_REGS(rbx);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RCX:
		return OFFSET_INTO_REGS(rcx);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDX:
		return OFFSET_INTO_REGS(rdx);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSI:
		return OFFSET_INTO_REGS(rsi);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDI:
		return OFFSET_INTO_REGS(rdi);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBP:
		return OFFSET_INTO_REGS(rbp);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSP:
		return OFFSET_INTO_REGS(rsp);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RIP:
		return OFFSET_INTO_REGS(rip);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RFLAGS:
		return OFFSET_INTO_REGS(eflags);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R8:
		return OFFSET_INTO_REGS(r8);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R9:
		return OFFSET_INTO_REGS(r9);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R10:
		return OFFSET_INTO_REGS(r10);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R11:
		return OFFSET_INTO_REGS(r11);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R12:
		return OFFSET_INTO_REGS(r12);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R13:
		return OFFSET_INTO_REGS(r13);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R14:
		return OFFSET_INTO_REGS(r14);

	case PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R15:
		return OFFSET_INTO_REGS(r15);

	default:
		// Not implemented.
		return -1;
	}

#undef OFFSET_INTO_REGS
}
