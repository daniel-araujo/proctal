#include "api/windows/proctal.h"

void proctal_windows_init(struct proctal_windows *pw)
{
	proctal_init(&pw->p);
}

void proctal_windows_deinit(struct proctal_windows *pw)
{
	proctal_deinit(&pw->p);
}

void proctal_windows_pid_set(struct proctal_windows *pw, DWORD process_id)
{
	pw->process_id = process_id;
}

DWORD proctal_windows_pid(struct proctal_windows *pw)
{
	return pw->process_id;
}
