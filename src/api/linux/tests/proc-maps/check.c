#include <stdlib.h>
#include <stdio.h>

#include "magic/magic.h"
#include "api/linux/proctal.h"
#include "api/linux/proc.h"

int main(void)
{
	struct test {
		const char *file;

		struct proctal_linux_proc_maps_region_check check;

		int expected_result;
	};

	struct test tests[] = {
		// Testing read permission.
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-with-read",

			.check = {
				.read = 1
			},

			.expected_result = 1
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-without-read",

			.check = {
				.read = 1
			},

			.expected_result = 0
		},

		// Testing write permission.
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-with-write",

			.check = {
				.write = 1
			},

			.expected_result = 1
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-without-write",

			.check = {
				.write = 1
			},

			.expected_result = 0
		},

		// Testing execute permission.
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-with-execute",

			.check = {
				.execute = 1
			},

			.expected_result = 1
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-without-execute",

			.check = {
				.execute = 1
			},

			.expected_result = 0
		},

		// Testing simple region matching.
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-heap",

			.check = {
				.mask = PROCTAL_REGION_HEAP,
			},

			.expected_result = 1
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-stack",

			.check = {
				.mask = PROCTAL_REGION_STACK,
			},

			.expected_result = 1
		},

		// Testing region mismatch.
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-heap",

			.check = {
				.mask = PROCTAL_REGION_STACK,
			},

			.expected_result = 0
		},

		// Testing a region that holds a specific permission.
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-with-execute",

			.check = {
				.mask = PROCTAL_REGION_HEAP,
				.execute = 1
			},

			.expected_result = 1
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-without-execute",

			.check = {
				.mask = PROCTAL_REGION_HEAP,
				.execute = 1
			},

			.expected_result = 0
		},

		// Testing that it's possible to match against multiple
		// regions.
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-stack",

			.check = {
				.mask = PROCTAL_REGION_STACK & PROCTAL_REGION_HEAP,
			},

			.expected_result = 1
		},
		{
			.file = PROCTAL_META_DIR_SRC "/api/linux/tests/proc-maps/sample-region-heap",

			.check = {
				.mask = PROCTAL_REGION_STACK & PROCTAL_REGION_HEAP,
			},

			.expected_result = 1
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

		int result = proctal_linux_proc_maps_region_check(region, &test->check);

		if (result != test->expected_result) {
			fprintf(stderr, "Unexpected result (%zu).\n", i);
			proctal_linux_proc_maps_close(&maps);
			return 1;
		}

		proctal_linux_proc_maps_close(&maps);
	}

	return 0;
}
