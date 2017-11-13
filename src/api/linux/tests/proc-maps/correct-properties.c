#include <stdlib.h>
#include <stdio.h>

#include "magic/magic.h"
#include "api/linux/proc.h"

int main(void)
{
	struct test {
		const char *file;

		void *expected_start;
		void *expected_end;
		int expected_read;
		int expected_write;
		int expected_execute;
		char *expected_name;
	};

	struct test tests[] = {
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-heap",

			.expected_start = (void *) 0x7fffb2c0d000,
			.expected_end = (void *) 0x7fffb2c2e000,
			.expected_read = 1,
			.expected_write = 1,
			.expected_execute = 0,
			.expected_name = "[heap]",
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-stack",

			.expected_start = (void *) 0x7fffb2c0d000,
			.expected_end = (void *) 0x7fffb2c2e000,
			.expected_read = 1,
			.expected_write = 1,
			.expected_execute = 0,
			.expected_name = "[stack]",
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-program-code",

			.expected_start = (void *) 0x7fffb2c0d000,
			.expected_end = (void *) 0x7fffb2c2e000,
			.expected_read = 1,
			.expected_write = 1,
			.expected_execute = 0,
			.expected_name = "/path/to/binary",
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-with-execute",

			.expected_start = (void *) 0x7fffb2c0d000,
			.expected_end = (void *) 0x7fffb2c2e000,
			.expected_read = 0,
			.expected_write = 0,
			.expected_execute = 1,
			.expected_name = "[stack]",
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-with-write",

			.expected_start = (void *) 0x7fffb2c0d000,
			.expected_end = (void *) 0x7fffb2c2e000,
			.expected_read = 0,
			.expected_write = 1,
			.expected_execute = 0,
			.expected_name = "[stack]",
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-with-read",

			.expected_start = (void *) 0x7fffb2c0d000,
			.expected_end = (void *) 0x7fffb2c2e000,
			.expected_read = 1,
			.expected_write = 0,
			.expected_execute = 0,
			.expected_name = "[stack]",
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-without-execute",

			.expected_start = (void *) 0x7fffb2c0d000,
			.expected_end = (void *) 0x7fffb2c2e000,
			.expected_read = 1,
			.expected_write = 1,
			.expected_execute = 0,
			.expected_name = "[stack]",
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-without-write",

			.expected_start = (void *) 0x7fffb2c0d000,
			.expected_end = (void *) 0x7fffb2c2e000,
			.expected_read = 1,
			.expected_write = 0,
			.expected_execute = 1,
			.expected_name = "[stack]",
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-without-read",

			.expected_start = (void *) 0x7fffb2c0d000,
			.expected_end = (void *) 0x7fffb2c2e000,
			.expected_read = 0,
			.expected_write = 1,
			.expected_execute = 1,
			.expected_name = "[stack]",
		},
	};

	for (size_t i = 0; i < ARRAY_SIZE(tests); ++i) {
		struct test *test = &tests[i];

		struct proctal_linux_proc_maps maps;

		if (!proctal_linux_proc_maps_fopen(&maps, test->file)) {
			fprintf(stderr, "Failed to open test file %s.\n", test->file);
			return 1;
		}

		struct proctal_linux_proc_maps_region *region;
		region = proctal_linux_proc_maps_read(&maps);

		if (region->start != test->expected_start) {
			fprintf(stderr, "Unexpected start address (%s).\n", test->file);
			proctal_linux_proc_maps_close(&maps);
			return 1;
		}

		if (region->end != test->expected_end) {
			fprintf(stderr, "Unexpected end address (%s).\n", test->file);
			proctal_linux_proc_maps_close(&maps);
			return 1;
		}

		if (region->read != test->expected_read) {
			fprintf(stderr, "Unexpected read permission (%s).\n", test->file);
			proctal_linux_proc_maps_close(&maps);
			return 1;
		}

		if (region->write != test->expected_write) {
			fprintf(stderr, "Unexpected write permission (%s).\n", test->file);
			proctal_linux_proc_maps_close(&maps);
			return 1;
		}

		if (region->execute != test->expected_execute) {
			fprintf(stderr, "Unexpected execute permission (%s).\n", test->file);
			proctal_linux_proc_maps_close(&maps);
			return 1;
		}

		size_t expected_name_size = strlen(test->expected_name);
		size_t name_size = proctal_darr_size(&region->name) - 1;

		if (expected_name_size != name_size ||
			strncmp(proctal_darr_data_const(&region->name), test->expected_name, expected_name_size) != 0) {
			fprintf(stderr, "Unexpected name in test (%s).\n", test->file);
			proctal_linux_proc_maps_close(&maps);
			return 1;
		}

		proctal_linux_proc_maps_close(&maps);
	}

	return 0;
}
