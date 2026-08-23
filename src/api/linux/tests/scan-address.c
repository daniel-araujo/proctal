#include <stdio.h>
#include <unistd.h>

#include "api/proctal.h"
#include "api/linux/proctal.h"
#include "api/linux/address.h"

int main(void)
{
	struct proctal_linux pl;
	proctal_linux_init(&pl);
	proctal_linux_pid_set(&pl, getpid());

	proctal_linux_scan_address_start(&pl);

	if (proctal_error(&pl.p)) {
		fprintf(stderr, "Failed to start scanning our own addresses.\n");
		return 1;
	}

	// With the default alignment of 1, consecutive addresses within the
	// same readable region are exactly 1 byte apart.

	void *previous = NULL;

	for (int i = 0; i < 3; i++) {
		void *address;

		if (!proctal_linux_scan_address_next(&pl, &address)) {
			fprintf(stderr, "Expected to find an address (call #%d).\n", i);
			return 1;
		}

		if (address == NULL) {
			fprintf(stderr, "Address was not set despite reporting success (call #%d).\n", i);
			return 1;
		}

		if (previous != NULL && (char *) address != (char *) previous + 1) {
			fprintf(stderr, "Expected consecutive addresses 1 byte apart (call #%d).\n", i);
			return 1;
		}

		previous = address;
	}

	proctal_linux_scan_address_stop(&pl);
	proctal_linux_deinit(&pl);

	return 0;
}
