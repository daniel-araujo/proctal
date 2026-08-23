#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>

#include "api/proctal.h"
#include "api/linux/proctal.h"
#include "api/linux/allocate.h"

int main(void)
{
	// We ptrace our own child, so this doesn't need any special
	// permissions.
	pid_t child = fork();

	if (child == 0) {
		for (;;) {
			pause();
		}
	}

	usleep(50000);

	struct proctal_linux pl;
	proctal_linux_init(&pl);
	proctal_linux_pid_set(&pl, child);

	int ret = 1;

	void *address = proctal_linux_allocate(&pl, sizeof(int));

	if (proctal_error(&pl.p) || address == NULL) {
		fprintf(stderr, "Failed to allocate in the child.\n");
		goto exit0;
	}

	proctal_linux_deallocate(&pl, address);

	if (proctal_error(&pl.p)) {
		fprintf(stderr, "Failed to deallocate a valid address.\n");
		goto exit0;
	}

	// Deallocating an address that was never allocated can't even be
	// read, so it must fail with a read failure instead of going on to
	// unmap garbage in the child.

	void *bogus = (void *) 1;
	proctal_linux_deallocate(&pl, bogus);

	if (proctal_error(&pl.p) != PROCTAL_ERROR_READ_FAILURE) {
		fprintf(stderr, "Expected a read failure deallocating an invalid address.\n");
		goto exit0;
	}

	proctal_error_recover(&pl.p);

	// The child, and our ability to keep operating on it, must not have
	// been affected by the invalid deallocate above.

	void *address2 = proctal_linux_allocate(&pl, sizeof(int));

	if (proctal_error(&pl.p) || address2 == NULL) {
		fprintf(stderr, "Child was left in a broken state by the invalid deallocate.\n");
		goto exit0;
	}

	proctal_linux_deallocate(&pl, address2);

	ret = 0;

exit0:
	proctal_linux_deinit(&pl);
	kill(child, SIGKILL);
	waitpid(child, NULL, 0);

	return ret;
}
