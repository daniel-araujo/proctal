#ifndef LINUX_PTRACE_H
#define LINUX_PTRACE_H

#define PROCTAL_LINUX_PTRACE_X86_REG_DR0 0x8000
#define PROCTAL_LINUX_PTRACE_X86_REG_DR1 0x8001
#define PROCTAL_LINUX_PTRACE_X86_REG_DR2 0x8002
#define PROCTAL_LINUX_PTRACE_X86_REG_DR3 0x8003
#define PROCTAL_LINUX_PTRACE_X86_REG_DR4 0x8004
#define PROCTAL_LINUX_PTRACE_X86_REG_DR5 0x8005
#define PROCTAL_LINUX_PTRACE_X86_REG_DR6 0x8006
#define PROCTAL_LINUX_PTRACE_X86_REG_DR7 0x8007

int proctal_linux_ptrace_attach(proctal p);
int proctal_linux_ptrace_detach(proctal p);

int proctal_linux_ptrace_stop(proctal p);
int proctal_linux_ptrace_cont(proctal p);

int proctal_linux_ptrace_get_instruction_address(proctal p, void **addr);

int proctal_linux_ptrace_set_x86_reg(proctal p, int reg, unsigned long long v);
int proctal_linux_ptrace_get_x86_reg(proctal p, int reg, unsigned long long *v);

#endif /* LINUX_PTRACE_H */
