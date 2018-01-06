#ifndef API_LINUX_PTRACE_H
#define API_LINUX_PTRACE_H

#include "api/linux/proctal.h"

// Register ids.
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RAX 0x0
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBX 0x1
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RCX 0x2
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDX 0x3
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSI 0x4
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RDI 0x5
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RBP 0x6
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RSP 0x7
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RIP 0x8
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_RFLAGS 0x9
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R8 0xA
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R9 0xB
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R10 0xC
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R11 0xD
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R12 0xE
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R13 0xF
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R14 0x10
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_R15 0x11
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR0 0x8000
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR1 0x8001
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR2 0x8002
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR3 0x8003
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR4 0x8004
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR5 0x8005
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR6 0x8006
#define PROCTAL_LINUX_PTRACE_REGISTER_X86_64_DR7 0x8007

/*
 * Holds a task's CPU state.
 */
struct proctal_linux_ptrace_cpu_state;

/*
 * Performs ptrace's attach function on all tasks of the program.
 *
 * You may attach to the same program multiple times.
 *
 * Returns 1 on success and 0 on failure.
 */
int proctal_linux_ptrace_attach(struct proctal_linux *pl);

/*
 * Performs ptrace's detach function on all tasks of the program.
 *
 * You can only detach as many times as you have attached.
 *
 * Returns 1 on success and 0 on failure.
 */
int proctal_linux_ptrace_detach(struct proctal_linux *pl);

/*
 * Same as proctal_linux_ptrace_detach but ignores the number of times that a
 * program was attached.
 */
void proctal_linux_ptrace_detach_force(struct proctal_linux *pl);

/*
 * Performs ptrace's stop function on the given task.
 *
 * If the id of the given task is 0, this will perform on all tasks.
 *
 * Does nothing and reports success if the task is already stopped.
 *
 * Returns 1 on success and 0 on failure.
 */
int proctal_linux_ptrace_stop(struct proctal_linux *pl, pid_t tid);

/*
 * Performs ptrace's continue function on the given task.
 *
 * If the id of the given task is 0, this will perform on all tasks.
 *
 * Does nothing and reports success if the task is already running.
 *
 * Returns 1 on success and 0 on failure.
 */
int proctal_linux_ptrace_cont(struct proctal_linux *pl, pid_t tid);

/*
 * Performs ptrace's step function on the given task.
 *
 * If the id of the given task is 0, this will perform on all tasks.
 *
 * Does nothing if the task is already running.
 *
 * Returns 1 on success and 0 on failure.
 */
int proctal_linux_ptrace_step(struct proctal_linux *pl, pid_t tid);

/*
 * Waits for a trap signal.
 *
 * If the id of the task is 0, will try to wait   
 *
 * Returns the id of the task
 */
pid_t proctal_linux_ptrace_wait_trap(struct proctal_linux *pl, pid_t tid);

/*
 * Checks whether the given task has stopped because of a trap signal.
 *
 * If the given id of the task is 0, will check all tasks of the program.
 *
 * Returns the id of the task or 0 if no task was stopped because of a trap.
 */
pid_t proctal_linux_ptrace_catch_trap(struct proctal_linux *pl, pid_t tid);

/*
 * Copies the value of the instruction pointer to address.
 *
 * Returns 1 on success, 0 on failure. On failure, the address remains
 * untouched.
 */
int proctal_linux_ptrace_instruction_pointer(struct proctal_linux *pl, pid_t tid, void **address);

/*
 * Sets the value of the instruction pointer.
 *
 * Returns 1 on success, 0 on failure. On failure, the instruction
 * pointer remains the same.
 */
int proctal_linux_ptrace_instruction_pointer_set(struct proctal_linux *pl, pid_t tid, void *address);

/*
 * Copies the value of a register to dst.
 *
 * This function assumes that dst points to a location that is large enough to
 * store the value.
 *
 * This function only works if the task is stopped.
 *
 * Returns 1 on success, 0 on failure. On failure, dst will not be
 * dereferenced.
 */
int proctal_linux_ptrace_register(struct proctal_linux *pl, pid_t tid, int regid, void *dst);

/*
 * Copies src to a register.
 *
 * This function only works if the task is stopped.
 *
 * Returns 1 on success, 0 on failure. On failure, the register remains
 * untouched.
 */
int proctal_linux_ptrace_register_set(struct proctal_linux *pl, pid_t tid, int regid, void *src);

/*
 * Creates a struct that can hold CPU state.
 *
 * Returns NULL on failure.
 */
struct proctal_linux_ptrace_cpu_state *proctal_linux_ptrace_cpu_state_create(struct proctal_linux *pl);

/*
 * Disposes the struct.
 */
void proctal_linux_ptrace_cpu_state_destroy(struct proctal_linux *pl, struct proctal_linux_ptrace_cpu_state *state);

/*
 * Saves the CPU state of the given task.
 *
 * This function only works if the task is stopped.
 *
 * Returns 1 on success, 0 on failure.
 */
int proctal_linux_ptrace_cpu_state_save(struct proctal_linux *pl, pid_t tid, struct proctal_linux_ptrace_cpu_state *state);

/*
 * Copies src to a register.
 *
 * This function only works if the task is stopped.
 *
 * Returns 1 on success, 0 on failure.
 */
int proctal_linux_ptrace_cpu_state_load(struct proctal_linux *pl, pid_t tid, struct proctal_linux_ptrace_cpu_state *state);

#endif /* API_LINUX_PTRACE_H */
