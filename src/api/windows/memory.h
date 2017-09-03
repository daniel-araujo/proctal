#ifndef API_WINDOWS_MEMORY_H
#define API_WINDOWS_MEMORY_H

#include <stdlib.h>

/*
 * Read from memory.
 *
 * Returns the number of bytes read. If that number does not match the
 * requested size, then it means that there was an error.
 */
size_t proctal_windows_memory_read(
	struct proctal_windows *pw,
	void *addr,
	char *out,
	size_t size);

/*
 * Write to memory.
 *
 * Returns the number of bytes written. If that number does not match the
 * given size, then it means that there was an error.
 */
size_t proctal_windows_memory_write(
	struct proctal_windows *pw,
	void *addr,
	const char *in,
	size_t size);

#endif /* API_WINDOWS_MEMORY_H */
