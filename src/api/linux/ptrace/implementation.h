#ifndef API_LINUX_PTRACE_IMPLEMENTATION_H
#define API_LINUX_PTRACE_IMPLEMENTATION_H

#include "api/linux/proctal.h"

/*
 * Copies the value of the instruction pointer to address.
 *
 * Returns 1 on success, 0 on failure. On failure, the address remains
 * untouched.
 */
int proctal_linux_ptrace_implementation_instruction_pointer(struct proctal_linux *pl, pid_t tid, void **address);

/*
 * Sets the value of the instruction pointer.
 *
 * Returns 1 on success, 0 on failure. On failure, the instruction
 * pointer remains the same.
 */
int proctal_linux_ptrace_implementation_instruction_pointer_set(struct proctal_linux *pl, pid_t tid, void *address);

/*
 * Copies the value of a register to dst.
 *
 * This function assumes that dst points to a location that is large enough to
 * store the value.
 *
 * Returns 1 on success, 0 on failure. On failure, dst shall not be
 * dereferenced.
 */
int proctal_linux_ptrace_implementation_register(struct proctal_linux *pl, pid_t tid, int regid, void *dst);

/*
 * Copies src to a register.
 *
 * Returns 1 on success, 0 on failure. On failure, the register remains
 * untouched.
 */
int proctal_linux_ptrace_implementation_register_set(struct proctal_linux *pl, pid_t tid, int regid, void *src);

/*
 * Must create an architecture specific cpu state.
 *
 * Must return NULL on failure.
 */
struct proctal_linux_ptrace_cpu_state *proctal_linux_ptrace_implementation_cpu_state_create(struct proctal_linux *pl);

/*
 * Must destroy an architecture specific cpu state.
 */
void proctal_linux_ptrace_implementation_cpu_state_destroy(struct proctal_linux *pl, struct proctal_linux_ptrace_cpu_state *state);

/*
 * Must save the current state of the cpu.
 *
 * Must return 1 on success, 0 on failure.
 */
int proctal_linux_ptrace_implementation_cpu_state_save(struct proctal_linux *pl, pid_t tid, struct proctal_linux_ptrace_cpu_state *state);

/*
 * Must set the state of the cpu.
 *
 * Must return 1 on success, 0 on failure.
 */
int proctal_linux_ptrace_implementation_cpu_state_load(struct proctal_linux *pl, pid_t tid, struct proctal_linux_ptrace_cpu_state *state);

#endif /* API_LINUX_PTRACE_IMPLEMENTATION_H */
