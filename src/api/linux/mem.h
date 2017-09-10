#ifndef API_LINUX_MEM_H
#define API_LINUX_MEM_H

#include <stdio.h>

#include "api/linux/proctal.h"

/*
 * Read from memory.
 *
 * Returns the number of bytes read. If that number does not match the
 * requested size, then it means that there was an error.
 */
size_t proctal_linux_mem_read(struct proctal_linux *pl, void *address, void *out, size_t size);

/*
 * Write to memory.
 *
 * Returns the number of bytes written. If that number does not match the
 * given size, then it means that there was an error.
 */
size_t proctal_linux_mem_write(struct proctal_linux *pl, void *address, const void *in, size_t size);

/*
 * Swaps the contents in memory at the given address with the contents pointed
 * to by src.
 *
 * Both dst and src may point to overlapped memory.
 *
 * Returns 1 on success and 0 on failure.
 */
int proctal_linux_mem_swap(struct proctal_linux *pl, void *address, void *dst, const void *src, size_t size);

/*
 * Finds a suitable place in memory marked as executable where you can write
 * the given number of bytes.
 *
 * Returns NULL on failure.
 */
void *proctal_linux_mem_find_payload_location(struct proctal_linux *pl, size_t size);

#endif /* API_LINUX_MEM_H */
