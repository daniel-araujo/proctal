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

/*
 * Saves the state of the given task.
 *
 * On success it returns a handle to a savestate. On failure it returns NULL.
 */
void *proctal_linux_execute_implementation_save_state(struct proctal_linux *pl, pid_t tid);

/*
 * Restores the state of the given task from a savestate.
 *
 * Returns 1 on success and 0 on failure.
 */
int proctal_linux_execute_implementation_load_state(struct proctal_linux *pl, pid_t tid, void *state);

/*
 * Creates stack frame.
 */
int proctal_linux_execute_implementation_create_stack_frame(struct proctal_linux *pl, pid_t tid);

/*
 * Destroys stack frame.
 */
int proctal_linux_execute_implementation_destroy_stack_frame(struct proctal_linux *pl, pid_t tid);

int proctal_linux_execute_implementation(
	struct proctal_linux *pl,
	const char *bytecode,
	size_t bytecode_length)
{
	int ret = 0;

	if (!proctal_linux_ptrace_attach(pl)) {
		goto exit0;
	}

	void *savestate = proctal_linux_execute_implementation_save_state(pl, pl->pid);

	if (savestate == NULL) {
		goto exit1;
	}

	if (!proctal_linux_execute_implementation_create_stack_frame(pl, pl->pid)) {
		goto exit2;
	}

	void *payload_location = proctal_linux_allocate(
		pl,
		proctal_linux_execute_implementation_no_op_code_size + bytecode_length + proctal_linux_execute_implementation_trap_code_size,
		PROCTAL_ALLOCATE_PERMISSION_WRITE | PROCTAL_ALLOCATE_PERMISSION_EXECUTE | PROCTAL_ALLOCATE_PERMISSION_READ);

	if (payload_location == NULL) {
		goto exit3;
	}

	void *no_op_code_location = payload_location;
	void *bytecode_location = (char *) no_op_code_location + proctal_linux_execute_implementation_no_op_code_size;
	void *trap_code_location = (char *) bytecode_location + bytecode_length;

	void *landing_zone = (char *) no_op_code_location + (proctal_linux_execute_implementation_no_op_code_size / 2);

	// Place payload.
	if (!proctal_linux_mem_write(pl, no_op_code_location, proctal_linux_execute_implementation_no_op_code, proctal_linux_execute_implementation_no_op_code_size)
		|| !proctal_linux_mem_write(pl, bytecode_location, bytecode, bytecode_length)
		|| !proctal_linux_mem_write(pl, trap_code_location, proctal_linux_execute_implementation_trap_code, proctal_linux_execute_implementation_trap_code_size)) {
		goto exit4;
	}

	// Execute payload. Will block until the trap signal is received.
	if (!proctal_linux_ptrace_instruction_pointer_set(pl, pl->pid, landing_zone)
		|| !proctal_linux_ptrace_cont(pl, pl->pid)
		|| !proctal_linux_ptrace_wait_trap(pl, pl->pid)) {
		goto exit4;
	}

	ret = 1;
exit4:
	proctal_linux_deallocate(pl, payload_location);
exit3:
	if (!proctal_linux_execute_implementation_destroy_stack_frame(pl, pl->pid)) {
		ret = 0;
	}
exit2:
	if (!proctal_linux_execute_implementation_load_state(pl, pl->pid, savestate)) {
		ret = 0;
	}
exit1:
	if (!proctal_linux_ptrace_detach(pl)) {
		ret = 0;
	}
exit0:
	return ret;
}
