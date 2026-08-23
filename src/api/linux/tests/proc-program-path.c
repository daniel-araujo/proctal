#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "api/linux/proc.h"

int main(void)
{
	// A PID that can never correspond to a running process, so the
	// "exe" symlink lookup is guaranteed to fail.
	const struct proctal_darr *bad = proctal_linux_program_path(0);

	if (bad != NULL) {
		fprintf(stderr, "Expected NULL for a nonexistent process.\n");
		proctal_linux_program_path_dispose(bad);
		return 1;
	}

	// A PID that does correspond to a running process (ourselves) should
	// resolve to the path of this test executable.

	char expected[4096];
	ssize_t expected_len = readlink("/proc/self/exe", expected, sizeof(expected) - 1);

	if (expected_len < 0) {
		fprintf(stderr, "Failed to read our own exe symlink.\n");
		return 1;
	}

	expected[expected_len] = '\0';

	const struct proctal_darr *path = proctal_linux_program_path(getpid());

	if (path == NULL) {
		fprintf(stderr, "Expected a valid path for our own PID.\n");
		return 1;
	}

	const char *got = proctal_darr_data_const(path);

	if (strcmp(got, expected) != 0) {
		fprintf(stderr, "Program path doesn't match what was expected.\n");
		proctal_linux_program_path_dispose(path);
		return 1;
	}

	proctal_linux_program_path_dispose(path);

	return 0;
}
