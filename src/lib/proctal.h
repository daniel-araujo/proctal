#ifndef PROCTAL_H
#define PROCTAL_H

#include <stddef.h>
#include <sys/types.h>

#define PROCTAL_ADDR_REGION_ALL 0
#define PROCTAL_ADDR_REGION_STACK 1
#define PROCTAL_ADDR_REGION_HEAP 2

typedef struct proctal *proctal;
typedef struct proctal_addr_iter *proctal_addr_iter;

/*
 * Creates and deletes an instance of Proctal.
 */
proctal proctal_create(void);
void proctal_destroy(proctal p);

/*
 * Sets and gets the Process ID for that instance of Proctal.
 *
 * When the returned value is 0, then that means no Process ID is associated.
 */
void proctal_set_pid(proctal p, pid_t pid);
pid_t proctal_pid(proctal p);

/*
 * Reads a specified length of characters starting from the given address. This
 * function assumes it can safely write the same length to the given buffer.
 *
 * There are also convenience functions for reading native C types.
 *
 * On success will return 0 and the given buffer will contain all characters
 * that were read.
 *
 * On failure will return a non-zero value. The contents of the given buffer
 * may or may not have been modifed.
 */
int proctal_read(proctal p, void *addr, char *out, size_t size);
int proctal_read_char(proctal p, void *addr, char *out);
int proctal_read_schar(proctal p, void *addr, signed char *out);
int proctal_read_uchar(proctal p, void *addr, unsigned char *out);
int proctal_read_short(proctal p, void *addr, short *out);
int proctal_read_ushort(proctal p, void *addr, unsigned short *out);
int proctal_read_int(proctal p, void *addr, int *out);
int proctal_read_uint(proctal p, void *addr, unsigned int *out);
int proctal_read_long(proctal p, void *addr, long *out);
int proctal_read_ulong(proctal p, void *addr, unsigned long *out);
int proctal_read_longlong(proctal p, void *addr, long long *out);
int proctal_read_ulonglong(proctal p, void *addr, unsigned long long *out);
int proctal_read_float(proctal p, void *addr, float *out);
int proctal_read_double(proctal p, void *addr, double *out);
int proctal_read_longdouble(proctal p, void *addr, long double *out);
int proctal_read_address(proctal p, void *addr, void **out);

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
int proctal_write(proctal p, void *addr, char *in, size_t size);
int proctal_write_char(proctal p, void *addr, char in);
int proctal_write_schar(proctal p, void *addr, signed char in);
int proctal_write_uchar(proctal p, void *addr, unsigned char in);
int proctal_write_short(proctal p, void *addr, short in);
int proctal_write_ushort(proctal p, void *addr, unsigned short in);
int proctal_write_int(proctal p, void *addr, int in);
int proctal_write_uint(proctal p, void *addr, unsigned int in);
int proctal_write_long(proctal p, void *addr, long in);
int proctal_write_ulong(proctal p, void *addr, unsigned long in);
int proctal_write_longlong(proctal p, void *addr, long long in);
int proctal_write_ulonglong(proctal p, void *addr, unsigned long long in);
int proctal_write_float(proctal p, void *addr, float in);
int proctal_write_double(proctal p, void *addr, double in);
int proctal_write_longdouble(proctal p, void *addr, long double in);
int proctal_write_address(proctal p, void *addr, void *in);

/*
 * Iterates over addresses in a process.
 *
 * Using the iterator is an elaborate process. You must first call
 * proctal_addr_iter_create. It will return an opaque data structure that
 * represents the iterator. With it you're allowed to call functions that alter
 * the behavior of the iterator, like proctal_addr_iter_set_align and
 * proctal_addr_iter_set_size.
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
proctal_addr_iter proctal_addr_iter_create(proctal p);
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
 * Sets and returns which address space regions are iterated.
 *
 * By default it's set to PROCTAL_ADDR_REGION_STACK | PROCTAL_ADDR_REGION_HEAP.
 *
 * Setting the mask to PROCTAL_ADDR_REGION_ALL will make it iterate over all
 * regions.
 *
 * Attempting to set a new value after retriving an address with the iterator
 * can cause undefined behavior. Don't do it.
 */
long proctal_addr_iter_region(proctal_addr_iter iter);
void proctal_addr_iter_set_region(proctal_addr_iter iter, long mask);

/*
 * Sets the memory allocator/deallocator used for internal data structures.
 *
 * These functions should only be called right after creating an instance of
 * Proctal so as to avoid a deallocator being called with an address returned
 * by a different allocator.
 */
void proctal_set_malloc(proctal p, void *(*malloc)(size_t));
void proctal_set_free(proctal p, void (*free)(void *));

/*
 * Global counterparts. These define the values that are used by default when
 * an instance of Proctal is created.
 *
 * If never called or passed NULL, will use the version of malloc/free that the
 * library was linked to.
 *
 * These functions must be called before any other function of the library so
 * as to avoid a deallocator being called with an address returned by a
 * different allocator.
 */
void proctal_global_set_malloc(void *(*malloc)(size_t));
void proctal_global_set_free(void (*free)(void *));

#endif /* PROCTAL_H */
