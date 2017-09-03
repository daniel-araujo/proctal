#ifndef API_WINDOWS_PROCTAL_H
#define API_WINDOWS_PROCTAL_H

#include <windows.h>

#include "api/proctal.h"

/*
 * Windows specific handle.
 */
struct proctal_windows {
	// Base structure.
	struct proctal p;

	// Process ID. This identifies the program we're going to muck with.
	DWORD process_id;

	// A handle to the program.
	HANDLE process_handle;
};

/*
 * Initializes a Windows specific handle.
 */
void proctal_windows_init(struct proctal_windows *pw);

/*
 * Deinitializes a Windows specific handle.
 */
void proctal_windows_deinit(struct proctal_windows *pw);

/*
 * Sets the PID.
 */
void proctal_windows_pid_set(struct proctal_windows *pw, DWORD process_id);

/*
 * Gets the PID.
 */
DWORD proctal_windows_pid(struct proctal_windows *pw);

#endif /* API_WINDOWS_PROCTAL_H */
