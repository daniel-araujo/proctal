#ifndef PROCTAL_H
#define PROCTAL_H

#include <stddef.h>
#include <sys/types.h>

/*
 * Reads a specified length of characters starting from an address in an other
 * process' memory space. This function assumes it can safely write the same
 * length to the given buffer.
 *
 * There are also convenience functions for reading native C types.
 *
 * On success will return 0 and the given buffer will contain all characters
 * that were read.
 *
 * On failure will return a non-zero value. The contents of the given buffer
 * may or may not have been modifed.
 */
int proctal_read(pid_t pid, void *addr, char *out, size_t size);
int proctal_read_char(pid_t pid, void *addr, char *out);
int proctal_read_schar(pid_t pid, void *addr, signed char *out);
int proctal_read_uchar(pid_t pid, void *addr, unsigned char *out);
int proctal_read_short(pid_t pid, void *addr, short *out);
int proctal_read_ushort(pid_t pid, void *addr, unsigned short *out);
int proctal_read_int(pid_t pid, void *addr, int *out);
int proctal_read_uint(pid_t pid, void *addr, unsigned int *out);
int proctal_read_long(pid_t pid, void *addr, long *out);
int proctal_read_ulong(pid_t pid, void *addr, unsigned long *out);
int proctal_read_longlong(pid_t pid, void *addr, long long *out);
int proctal_read_ulonglong(pid_t pid, void *addr, unsigned long long *out);
int proctal_read_float(pid_t pid, void *addr, float *out);
int proctal_read_double(pid_t pid, void *addr, double *out);
int proctal_read_longdouble(pid_t pid, void *addr, long double *out);

/*
 * Writes a specified length of characters starting from an address in an other
 * process' memory space. This function assumes it can safely access the same
 * length in the given buffer.
 *
 * There are also convenience functions for writing native C types.
 *
 * On success will return 0.
 *
 * On failure will return a non-zero value. The contents of the given buffer
 * may or may not have been partially written to the address space of the other
 * process.
 */
int proctal_write(pid_t pid, void *addr, char *in, size_t size);
int proctal_write_char(pid_t pid, void *addr, char in);
int proctal_write_schar(pid_t pid, void *addr, signed char in);
int proctal_write_uchar(pid_t pid, void *addr, unsigned char in);
int proctal_write_short(pid_t pid, void *addr, short in);
int proctal_write_ushort(pid_t pid, void *addr, unsigned short in);
int proctal_write_int(pid_t pid, void *addr, int in);
int proctal_write_uint(pid_t pid, void *addr, unsigned int in);
int proctal_write_long(pid_t pid, void *addr, long in);
int proctal_write_ulong(pid_t pid, void *addr, unsigned long in);
int proctal_write_longlong(pid_t pid, void *addr, long long in);
int proctal_write_ulonglong(pid_t pid, void *addr, unsigned long long in);
int proctal_write_float(pid_t pid, void *addr, float in);
int proctal_write_double(pid_t pid, void *addr, double in);
int proctal_write_longdouble(pid_t pid, void *addr, long double in);

#endif /* PROCTAL_H */
