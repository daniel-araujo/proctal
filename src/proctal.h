#ifndef PROCTAL_H
#define PROCTAL_H

#include <stddef.h>
#include <sys/types.h>

typedef struct proctal_addr_iter *proctal_addr_iter;

typedef void *(*proctal_malloc)(size_t);
typedef void (*proctal_free)(void *);

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

/*
 * Iterates over every address of a process.
 *
 * Using the iterator is an elaborate process. You must first call
 * proctal_addr_iter_create with a Process ID. It will return an opaque data
 * structure that represents the iterator. With it you're allowed to call
 * functions that alter the behavior of the iterator, like
 * proctal_addr_iter_set_align and proctal_addr_iter_set_size.
 *
 * With the iterator configured to your liking, you can query addresses by
 * multiple calls to proctal_addr_iter_next. At this point you can no longer
 * configure the behavior of the iterator. The function returns 0 on success, 1
 * after the last successful call to the function had returned the last address
 * and -1 on failure.
 *
 * Once you're done iterating, you can call proctal_addr_iter_finish to declare
 * the iterator data structure as garbage or proctal_addr_iter_restart to get
 * to the same stage after a call to proctal_addr_iter_create while retaining
 * your custom configuration.
 */
proctal_addr_iter proctal_addr_iter_create(pid_t pid);
int proctal_addr_iter_next(proctal_addr_iter iter, void **addr);
void proctal_addr_iter_destroy(proctal_addr_iter iter);
void proctal_addr_iter_restart(proctal_addr_iter iter);

/*
 * Sets and returns the alignment requirements of the addresses to be iterated.
 *
 * Attempting to set a new value after retriving an address with the iterator
 * can cause undefined behavior. Don't do it.
 */
size_t proctal_addr_iter_align(proctal_addr_iter iter);
void proctal_addr_iter_set_align(proctal_addr_iter iter, size_t align);

/*
 * Sets and returns the size of the values pointed to by the addresses to be
 * iterated.
 *
 * Attempting to set a new value after retriving an address with the iterator
 * can cause undefined behavior. Don't do it.
 */
size_t proctal_addr_iter_size(proctal_addr_iter iter);
void proctal_addr_iter_set_size(proctal_addr_iter iter, size_t size);

/*
 * Sets the memory allocator/deallocator used for internal data structures.
 *
 * If never called or passed NULL, will use the version of malloc/free that the
 * library was linked to.
 *
 * These functions must be called before any other function of the library so
 * as to avoid a deallocator being called with an address returned by a
 * different allocator.
 */
void proctal_set_malloc(proctal_malloc new);
void proctal_set_free(proctal_free new);

#endif /* PROCTAL_H */
