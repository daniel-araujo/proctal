#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "api/proctal.h"
#include "api/linux/proctal.h"
#include "api/linux/mem.h"

int main(void)
{
	struct proctal_linux pl;
	proctal_linux_init(&pl);
	proctal_linux_pid_set(&pl, getpid());

	// Reading and writing our own memory should just work.

	int value = 1234;
	int read_value = 0;

	if (!proctal_linux_mem_read(&pl, &value, &read_value, sizeof(read_value))) {
		fprintf(stderr, "Failed to read valid address.\n");
		return 1;
	}

	if (read_value != value) {
		fprintf(stderr, "Read value doesn't match what was expected.\n");
		return 1;
	}

	int new_value = 5678;

	if (!proctal_linux_mem_write(&pl, &value, &new_value, sizeof(new_value))) {
		fprintf(stderr, "Failed to write to valid address.\n");
		return 1;
	}

	if (value != new_value) {
		fprintf(stderr, "Write didn't actually change the value.\n");
		return 1;
	}

	// An address that makes fseek fail (a negative offset) must be
	// reported as a read/write failure instead of silently reading or
	// writing at the previous stream position.

	void *bad_address = (void *) -1;

	if (proctal_linux_mem_read(&pl, bad_address, &read_value, sizeof(read_value))) {
		fprintf(stderr, "Expected read from bad address to fail.\n");
		return 1;
	}

	if (proctal_error(&pl.p) != PROCTAL_ERROR_READ_FAILURE) {
		fprintf(stderr, "Expected a read failure error to be set.\n");
		return 1;
	}

	proctal_error_recover(&pl.p);

	if (proctal_linux_mem_write(&pl, bad_address, &new_value, sizeof(new_value))) {
		fprintf(stderr, "Expected write to bad address to fail.\n");
		return 1;
	}

	if (proctal_error(&pl.p) != PROCTAL_ERROR_WRITE_FAILURE) {
		fprintf(stderr, "Expected a write failure error to be set.\n");
		return 1;
	}

	proctal_error_recover(&pl.p);

	proctal_linux_deinit(&pl);

	return 0;
}
