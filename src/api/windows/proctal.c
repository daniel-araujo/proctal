#include "api/windows/proctal.h"

static int open_process(struct proctal_windows *pw)
{
	if (pw->process_id == 0) {
		// Can't open this.
		proctal_error_set(&pw->p, PROCTAL_ERROR_PERMISSION_DENIED);
		return 0;
	}

	DWORD access = PROCESS_VM_READ | PROCESS_VM_WRITE;

	pw->process_handle = OpenProcess(access, FALSE, pw->process_id);

	if (pw->process_handle == NULL) {
		// TODO: Check error code.
		pw->process_id = 0;
		proctal_error_set(&pw->p, PROCTAL_ERROR_PROGRAM_UNTAMEABLE);
		return 0;
	}

	return 1;
}

static int close_process(struct proctal_windows *pw)
{
	if (pw->process_id == 0) {
		// Nothing to close.
		return 1;
	}

	if (!CloseHandle(pw->process_handle)) {
		// TODO: Check error code.
		pw->process_id = 0;
		proctal_error_set(&pw->p, PROCTAL_ERROR_PROGRAM_UNTAMEABLE);
		return 0;
	}

	return 1;
}

void proctal_windows_init(struct proctal_windows *pw)
{
	proctal_init(&pw->p);

	pw->process_id = 0;
}

void proctal_windows_deinit(struct proctal_windows *pw)
{
	close_process(pw);

	proctal_deinit(&pw->p);
}

void proctal_windows_pid_set(struct proctal_windows *pw, DWORD process_id)
{
	close_process(pw);

	pw->process_id = process_id;

	open_process(pw);
}

DWORD proctal_windows_pid(struct proctal_windows *pw)
{
	return pw->process_id;
}
