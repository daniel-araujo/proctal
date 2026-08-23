#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "api/linux/proctal.h"
#include "api/linux/proc.h"

int main(void)
{
	// An anonymous region (no name) must not crash and must not be
	// considered a match.
	{
		struct proctal_linux_proc_maps_region region;
		region.execute = 1;
		proctal_darr_init(&region.name, sizeof(char));

		struct proctal_linux_proc_maps_region_check check = {
			.pid = getpid(),
			.mask = PROCTAL_REGION_PROGRAM_CODE,
		};

		int result = proctal_linux_proc_maps_region_check(&region, &check);

		proctal_darr_deinit(&region.name);

		if (result != 0) {
			fprintf(stderr, "Expected no match for an anonymous region.\n");
			return 1;
		}
	}

	// A PID that can't have its program path resolved must not crash and
	// must not be considered a match.
	{
		struct proctal_linux_proc_maps_region region;
		region.execute = 1;
		proctal_darr_init(&region.name, sizeof(char));

		const char *name = "/some/path";
		proctal_darr_resize(&region.name, strlen(name) + 1);
		strcpy(proctal_darr_data(&region.name), name);

		struct proctal_linux_proc_maps_region_check check = {
			.pid = 0,
			.mask = PROCTAL_REGION_PROGRAM_CODE,
		};

		int result = proctal_linux_proc_maps_region_check(&region, &check);

		proctal_darr_deinit(&region.name);

		if (result != 0) {
			fprintf(stderr, "Expected no match for an unresolvable PID.\n");
			return 1;
		}
	}

	// A region named after our own program's path must be a match.
	{
		char expected[4096];
		ssize_t n = readlink("/proc/self/exe", expected, sizeof(expected) - 1);

		if (n < 0) {
			fprintf(stderr, "Failed to read our own exe symlink.\n");
			return 1;
		}

		expected[n] = '\0';

		struct proctal_linux_proc_maps_region region;
		region.execute = 1;
		proctal_darr_init(&region.name, sizeof(char));
		proctal_darr_resize(&region.name, (size_t) n + 1);
		memcpy(proctal_darr_data(&region.name), expected, (size_t) n + 1);

		struct proctal_linux_proc_maps_region_check check = {
			.pid = getpid(),
			.mask = PROCTAL_REGION_PROGRAM_CODE,
		};

		int result = proctal_linux_proc_maps_region_check(&region, &check);

		proctal_darr_deinit(&region.name);

		if (result != 1) {
			fprintf(stderr, "Expected a match for our own program path.\n");
			return 1;
		}
	}

	return 0;
}
