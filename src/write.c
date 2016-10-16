#include <stdio.h>
#include <stdlib.h>

#include "proctal.h"

void proctal_write_memory(
	proctal_process process,
	proctal_process_memory_address addr,
	proctal_stream stream)
{
}

void proctal_write_memory_int(
	proctal_process process,
	proctal_process_memory_address addr,
	int val)
{
	int pid = proctal_process_get_pid(process);

	char path_template[] = "/proc/%d/mem";
	char path[sizeof(path_template) + 11];
	snprintf(path, sizeof path, path_template, pid);

	FILE *f = fopen(path, "w");

	if (f == NULL) {
		return;
	}

	fseek(f, proctal_process_memory_address_get_offset(addr), SEEK_SET);

	fwrite(&val, 4, 1, f);
}
