#include <stdlib.h>
#include <stdio.h>

#include "proctal.h"

proctal_stream proctal_read_memory(
	proctal_process process,
	proctal_process_memory_address addr,
	int size)
{
	return proctal_stream_create(NULL, 0);
}

int proctal_read_memory_int(
	proctal_process process,
	proctal_process_memory_address addr)
{
	int pid = proctal_process_get_pid(process);

	char path_template[] = "/proc/%d/mem";
	char path[sizeof(path_template) + 11];
	snprintf(path, sizeof path, path_template, pid);

	FILE *f = fopen(path, "r");

	if (f == NULL) {
		return 0;
	}

	fseek(f, proctal_process_memory_address_get_offset(addr), SEEK_SET);

	int val;

	fread(&val, 4, 1, f);

	return val;
}
