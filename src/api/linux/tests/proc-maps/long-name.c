#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api/linux/proctal.h"
#include "api/linux/proc.h"

int main(void)
{
	// Long enough to cross a few of the buffer's growth boundaries
	// (255 -> 510 -> 1020 bytes).
	size_t name_len = 600;
	char name[601];

	for (size_t i = 0; i < name_len; i++) {
		name[i] = 'a' + (i % 26);
	}
	name[name_len] = '\0';

	char line[700];
	snprintf(line, sizeof(line), "7f0000000000-7f0000001000 r-xp 00000000 08:01 123456    %s\n", name);

	FILE *f = tmpfile();

	if (f == NULL) {
		fprintf(stderr, "Failed to create a temporary file.\n");
		return 1;
	}

	fputs(line, f);
	rewind(f);

	struct proctal_linux_proc_maps maps;
	maps.file = f;
	proctal_darr_init(&maps.current.name, sizeof(char));

	struct proctal_linux_proc_maps_region *region = proctal_linux_proc_maps_read(&maps);

	int ret = 0;

	if (region == NULL) {
		fprintf(stderr, "Failed to read a region with a long name.\n");
		ret = 1;
		goto exit0;
	}

	if (strcmp(proctal_darr_data_const(&region->name), name) != 0) {
		fprintf(stderr, "Region name doesn't match what was expected.\n");
		ret = 1;
		goto exit0;
	}

exit0:
	proctal_darr_deinit(&maps.current.name);
	fclose(f);

	return ret;
}
