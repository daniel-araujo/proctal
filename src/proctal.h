#ifndef PROCTAL_H
#define PROCTAL_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Reads a specified length of characters starting from an address in an other
 * process' memory space. This function assumes it can safely write the same
 * length to the given buffer.
 *
 * On success will return 0 and the given buffer will contain all characters
 * that were read.
 *
 * On failure will return a non-zero value. The contents of the given buffer
 * may or may not have been modifed.
 */
int proctal_mem_read(pid_t pid, void *addr, char *out, size_t size);

/*
 * Convenient function to read an int.
 */
int proctal_mem_read_int(pid_t pid, void *addr, int *out);

/*
 * Convenient function to read an unsigned int.
 */
int proctal_mem_read_uint(pid_t pid, void *addr, unsigned int *out);

/*
 * Writes a specified length of characters starting from an address in an other
 * process' memory space. This function assumes it can safely access the same
 * length in the given buffer.
 *
 * On success will return 0.
 *
 * On failure will return a non-zero value. The contents of the given buffer
 * may or may not have been partially written to the address space of the other
 * process.
 */
int proctal_mem_write(pid_t pid, void *addr, char *in, size_t size);

/*
 * Convenient function to write an int.
 */
int proctal_mem_write_int(pid_t pid, void *addr, int in);

/*
 * Convenient function to write an unsigned int.
 */
int proctal_mem_write_uint(pid_t pid, void *addr, unsigned int in);

#endif /* PROCTAL_H */
