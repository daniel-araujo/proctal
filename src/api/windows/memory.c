#include <windows.h>

#include "api/windows/proctal.h"

size_t proctal_windows_memory_read(struct proctal_windows *pw, void *address, void *out, size_t size)
{
	SIZE_T read = 0;

	ReadProcessMemory(pw->process_handle, address, out, size, &read);

	if (read != size) {
		proctal_error_set(&pw->p, PROCTAL_ERROR_READ_FAILURE);
	}

	return read;
}

size_t proctal_windows_memory_write(struct proctal_windows *pw, void *address, const void *in, size_t size)
{
	SIZE_T written = 0;

	WriteProcessMemory(pw->process_handle, address, in, size, &written);

	if (written != size) {
		proctal_error_set(&pw->p, PROCTAL_ERROR_WRITE_FAILURE);
	}

	return written;
}
