#ifndef PROCTAL_H
#define PROCTAL_H

#include <stddef.h>
#include <sys/types.h>

#define PROCTAL_ADDR_REGION_STACK 1
#define PROCTAL_ADDR_REGION_HEAP 2

#define PROCTAL_ERROR_OUT_OF_MEMORY 1
#define PROCTAL_ERROR_PERMISSION_DENIED 2
#define PROCTAL_ERROR_WRITE_FAILURE 3
#define PROCTAL_ERROR_READ_FAILURE 4
#define PROCTAL_ERROR_UNKNOWN 5

typedef struct proctal *proctal;
typedef struct proctal_addr_iter *proctal_addr_iter;

/*
 * Creates and deletes an instance of Proctal.
 *
 * There's always a tiny chance that creating an instance fails, such as when
 * running out of memory, so you're better off calling proctal_error right
 * after calling this function to make sure you don't use an invalid instance.
 * Regardless if it succeeds or fails, you still need to call proctal_destroy.
 * Do not compare it to NULL.
 *
 * Using an invalid instance of Proctal results in undefined behavior.
 */
proctal proctal_create(void);
void proctal_destroy(proctal p);

/*
 * Use this function to check if something ever went wrong with the given
 * instance of Proctal.
 *
 * Any truthy value returned indicates an error which is one of PROCTAL_ERROR_*
 * defined constants. The only falsy value it can return is 0 which means there
 * are no errors to report.
 *
 * This function always returns the last error until you acknowledge it with a
 * call to proctal_error_ack.
 */
int proctal_error(proctal p);

/*
 * Allows you to acknowledge the last error that ocurred with the given
 * instance of Proctal, essentially making Proctal forget about its erroneous
 * past.
 */
void proctal_error_ack(proctal p);

/*
 * Similar to proctal_error, but returns pointers to read-only C-style strings
 * for diagnostic purposes such as logging. NULL is returned as the only falsy
 * value which indicates no error.
 *
 * These messages are in English and are not suitable for displaying to the
 * user.
 */
const char *proctal_error_msg(proctal p);

/*
 * Sets and gets the Process ID for that instance of Proctal.
 *
 * When the returned value is 0 then it means no Process ID is associated.
 */
void proctal_set_pid(proctal p, pid_t pid);
pid_t proctal_pid(proctal p);

/*
 * Reads a specified length of characters starting from the given address. This
 * function assumes it can safely write the same length to the given buffer.
 *
 * Will return the number of characters it successfuly reads.
 *
 * Not returning the expect number of values indicates an error.
 *
 * There are also convenience functions for reading native C types. Sizes
 * correspond to the type's size.
 */
size_t proctal_read(proctal p, void *addr, char *out, size_t size);
size_t proctal_read_char(proctal p, void *addr, char *out);
size_t proctal_read_char_array(proctal p, void *addr, char *out, size_t size);
size_t proctal_read_schar(proctal p, void *addr, signed char *out);
size_t proctal_read_schar_array(proctal p, void *addr, signed char *out, size_t size);
size_t proctal_read_uchar(proctal p, void *addr, unsigned char *out);
size_t proctal_read_uchar_array(proctal p, void *addr, unsigned char *out, size_t size);
size_t proctal_read_short(proctal p, void *addr, short *out);
size_t proctal_read_short_array(proctal p, void *addr, short *out, size_t size);
size_t proctal_read_ushort(proctal p, void *addr, unsigned short *out);
size_t proctal_read_ushort_array(proctal p, void *addr, unsigned short *out, size_t size);
size_t proctal_read_int(proctal p, void *addr, int *out);
size_t proctal_read_int_array(proctal p, void *addr, int *out, size_t size);
size_t proctal_read_uint(proctal p, void *addr, unsigned int *out);
size_t proctal_read_uint_array(proctal p, void *addr, unsigned int *out, size_t size);
size_t proctal_read_long(proctal p, void *addr, long *out);
size_t proctal_read_long_array(proctal p, void *addr, long *out, size_t size);
size_t proctal_read_ulong(proctal p, void *addr, unsigned long *out);
size_t proctal_read_ulong_array(proctal p, void *addr, unsigned long *out, size_t size);
size_t proctal_read_longlong(proctal p, void *addr, long long *out);
size_t proctal_read_longlong_array(proctal p, void *addr, long long *out, size_t size);
size_t proctal_read_ulonglong(proctal p, void *addr, unsigned long long *out);
size_t proctal_read_ulonglong_array(proctal p, void *addr, unsigned long long *out, size_t size);
size_t proctal_read_float(proctal p, void *addr, float *out);
size_t proctal_read_float_array(proctal p, void *addr, float *out, size_t size);
size_t proctal_read_double(proctal p, void *addr, double *out);
size_t proctal_read_double_array(proctal p, void *addr, double *out, size_t size);
size_t proctal_read_longdouble(proctal p, void *addr, long double *out);
size_t proctal_read_longdouble_array(proctal p, void *addr, long double *out, size_t size);
size_t proctal_read_address(proctal p, void *addr, void **out);
size_t proctal_read_address_array(proctal p, void *addr, void **out, size_t size);

/*
 * Writes a specified length of characters starting from an address in an other
 * process' memory space. This function assumes it can safely access the same
 * length in the given buffer.
 *
 * Will return the number of characters it successfuly writes.
 *
 * Not returning the expect number of values indicates an error.
 *
 * There are also convenience functions for writing native C types. Sizes
 * correspond to the type's size.
 */
size_t proctal_write(proctal p, void *addr, char *in, size_t size);
size_t proctal_write_char(proctal p, void *addr, char in);
size_t proctal_write_char_array(proctal p, void *addr, char *in, size_t size);
size_t proctal_write_schar(proctal p, void *addr, signed char in);
size_t proctal_write_schar_array(proctal p, void *addr, signed char *in, size_t size);
size_t proctal_write_uchar(proctal p, void *addr, unsigned char in);
size_t proctal_write_uchar_array(proctal p, void *addr, unsigned char *in, size_t size);
size_t proctal_write_short(proctal p, void *addr, short in);
size_t proctal_write_short_array(proctal p, void *addr, short *in, size_t size);
size_t proctal_write_ushort(proctal p, void *addr, unsigned short in);
size_t proctal_write_ushort_array(proctal p, void *addr, unsigned short *in, size_t size);
size_t proctal_write_int(proctal p, void *addr, int in);
size_t proctal_write_int_array(proctal p, void *addr, int *in, size_t size);
size_t proctal_write_uint(proctal p, void *addr, unsigned int in);
size_t proctal_write_uint_array(proctal p, void *addr, unsigned int *in, size_t size);
size_t proctal_write_long(proctal p, void *addr, long in);
size_t proctal_write_long_array(proctal p, void *addr, long *in, size_t size);
size_t proctal_write_ulong(proctal p, void *addr, unsigned long in);
size_t proctal_write_ulong_array(proctal p, void *addr, unsigned long *in, size_t size);
size_t proctal_write_longlong(proctal p, void *addr, long long in);
size_t proctal_write_longlong_array(proctal p, void *addr, long long *in, size_t size);
size_t proctal_write_ulonglong(proctal p, void *addr, unsigned long long in);
size_t proctal_write_ulonglong_array(proctal p, void *addr, unsigned long long *in, size_t size);
size_t proctal_write_float(proctal p, void *addr, float in);
size_t proctal_write_float_array(proctal p, void *addr, float *in, size_t size);
size_t proctal_write_double(proctal p, void *addr, double in);
size_t proctal_write_double_array(proctal p, void *addr, double *in, size_t size);
size_t proctal_write_longdouble(proctal p, void *addr, long double in);
size_t proctal_write_longdouble_array(proctal p, void *addr, long double *in, size_t size);
size_t proctal_write_address(proctal p, void *addr, void *in);
size_t proctal_write_address_array(proctal p, void *addr, void **in, size_t size);

/*
 * Iterates over addresses in a process.
 *
 * Using the iterator is an elaborate process. You must first call
 * proctal_addr_iter_create. It will return an opaque data structure that
 * represents the iterator. With it you're allowed to call functions that alter
 * the behavior of the iterator, like proctal_addr_iter_set_align and
 * proctal_addr_iter_set_size. This function can fail, so you should call
 * proctal_error right after it to make sure nothing went wrong with it.
 * On failure you do not need to call proctal_addr_iter_destroy. Do not
 * compare it to NULL.
 *
 * With the iterator configured to your liking, you can query addresses by
 * multiple calls to proctal_addr_iter_next. At this point you can no longer
 * configure the behavior of the iterator. The function returns 1 on success, 0
 * after the last successful call to the function had returned the last address
 * and on failure. To check that it returned 0 because of a failure, call
 * proctal_error
 *
 * Once you're done iterating, you can call proctal_addr_iter_destroy to declare
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
 * Setting the mask to 0 will make it iterate over all regions.
 *
 * Attempting to set a new value after retriving an address with the iterator
 * can cause undefined behavior. Don't do it.
 */
long proctal_addr_iter_region(proctal_addr_iter iter);
void proctal_addr_iter_set_region(proctal_addr_iter iter, long mask);

/*
 * Freezes and unfreezes main thread of execution.
 *
 * You should unfreeze before destroying or exiting your program otherwise it
 * will cause undefined behavior.
 */
int proctal_freeze(proctal p);
int proctal_unfreeze(proctal p);

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
