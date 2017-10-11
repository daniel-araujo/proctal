#include <stdlib.h>
#include <stdio.h>

#include "magic/magic.h"
#include "api/linux/proc.h"

int main(void)
{
	struct test {
		int pid;
		const char *file;
		const char *expected_path;
	};

	struct test tests[] = {
		{
			.pid = 12345,
			.file = "maps",
			.expected_path = "/proc/12345/maps",
		},
		{
			.pid = 1,
			.file = "maps",
			.expected_path = "/proc/1/maps",
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); ++i) {
		struct test *test = &tests[i];

		const struct proctal_darr *path = proctal_linux_proc_path(test->pid, test->file);

		size_t expected_size = strlen(test->expected_path);

		if (proctal_darr_size(path) != expected_size) {
			fprintf(stderr, "Unexpected size in test #%d.\n", (int) i);
			proctal_linux_proc_path_dispose(path);
			return 1;
		}

		if (strncmp(test->expected_path, proctal_darr_data_const(path), expected_size) != 0) {
			fprintf(stderr, "Unexpected path in test #%d.\n", (int) i);
			proctal_linux_proc_path_dispose(path);
			return 1;
		}

		proctal_linux_proc_path_dispose(path);
	}

	return 0;
}
