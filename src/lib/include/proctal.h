#ifndef PROCTAL_H
#define PROCTAL_H

/*
 * These bring up type definitions used in the following function declarations.
 * They are included here for your convenience, allowing you to include this
 * header without having to worry about what you'd need to include beforehand.
 */
#include <stddef.h>

/*
 * Macro definitions of all error codes, such as those returned by a call to
 * proctal_error.
 */
#define PROCTAL_ERROR_OUT_OF_MEMORY 1
#define PROCTAL_ERROR_PERMISSION_DENIED 2
#define PROCTAL_ERROR_WRITE_FAILURE 3
#define PROCTAL_ERROR_READ_FAILURE 4
#define PROCTAL_ERROR_UNKNOWN 5
#define PROCTAL_ERROR_UNIMPLEMENTED 6
#define PROCTAL_ERROR_UNSUPPORTED 7
#define PROCTAL_ERROR_UNSUPPORTED_WATCH_READ 8
#define PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_EXECUTE 9
#define PROCTAL_ERROR_UNSUPPORTED_WATCH_WRITE_EXECUTE 10
#define PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_WRITE_EXECUTE 11
#define PROCTAL_ERROR_PROCESS_NOT_FOUND 12
#define PROCTAL_ERROR_PROCESS_NOT_SET 13
#define PROCTAL_ERROR_INJECT_ADDR_NOT_FOUND 14

/*
 * Macro definitions of known address regions.
 */
#define PROCTAL_ADDR_REGION_STACK 1
#define PROCTAL_ADDR_REGION_HEAP 2

/*
 * Macro definitions of memory allocation permissions.
 */
#define PROCTAL_ALLOC_PERM_EXECUTE 1
#define PROCTAL_ALLOC_PERM_WRITE 2
#define PROCTAL_ALLOC_PERM_READ 4

/*
 * Types.
 */
typedef struct proctal *proctal;
typedef struct proctal_watch *proctal_watch;
typedef struct proctal_addr_iter *proctal_addr_iter;

/*
 * Creates and destroys an instance of Proctal.
 *
 * There is always a tiny chance that this call may fail such as when the
 * system is running out of memory therefore you should call proctal_error
 * right after. And regardless of it succeeding or failing you still need to
 * call proctal_destroy.
 *
 * Using an instance of Proctal that failed to be created correctly will result
 * in undefined behavior, likely leading to a crash.
 */
proctal proctal_create(void);
void proctal_destroy(proctal p);

/*
 * Allows you to check if an error happened with the given instance of Proctal.
 *
 * Any non-zero value that is returned is an error code. Error codes are
 * defined as macros whose name start with PROCTAL_ERROR. A 0 return value
 * means there is no error.
 *
 * This function will keep reporting the same error until you acknowledge it
 * with a call to proctal_error_ack.
 */
int proctal_error(proctal p);

/*
 * Allows you to acknowledge the error that occurred with the given instance of
 * Proctal, essentially making Proctal forget about its erroneous past.
 *
 * This function will do nothing if the given instance of Proctal has no error.
 */
void proctal_error_ack(proctal p);

/*
 * Similar to proctal_error, but returns pointers to read-only C-style strings
 * for diagnostic purposes such as logging. NULL is returned to indicate no
 * error.
 *
 * These messages are in English and are not suitable for displaying to the
 * user.
 */
const char *proctal_error_msg(proctal p);

/*
 * Sets the Process ID (PID) for the given instance of Proctal.
 */
void proctal_set_pid(proctal p, int pid);

/*
 * Returns the Process ID (PID) from the given instance of Proctal.
 */
int proctal_pid(proctal p);

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
size_t proctal_write(proctal p, void *addr, const char *in, size_t size);
size_t proctal_write_char(proctal p, void *addr, char in);
size_t proctal_write_char_array(proctal p, void *addr, const char *in, size_t size);
size_t proctal_write_schar(proctal p, void *addr, signed char in);
size_t proctal_write_schar_array(proctal p, void *addr, const signed char *in, size_t size);
size_t proctal_write_uchar(proctal p, void *addr, unsigned char in);
size_t proctal_write_uchar_array(proctal p, void *addr, const unsigned char *in, size_t size);
size_t proctal_write_short(proctal p, void *addr, short in);
size_t proctal_write_short_array(proctal p, void *addr, const short *in, size_t size);
size_t proctal_write_ushort(proctal p, void *addr, unsigned short in);
size_t proctal_write_ushort_array(proctal p, void *addr, const unsigned short *in, size_t size);
size_t proctal_write_int(proctal p, void *addr, int in);
size_t proctal_write_int_array(proctal p, void *addr, const int *in, size_t size);
size_t proctal_write_uint(proctal p, void *addr, unsigned int in);
size_t proctal_write_uint_array(proctal p, void *addr, const unsigned int *in, size_t size);
size_t proctal_write_long(proctal p, void *addr, long in);
size_t proctal_write_long_array(proctal p, void *addr, const long *in, size_t size);
size_t proctal_write_ulong(proctal p, void *addr, unsigned long in);
size_t proctal_write_ulong_array(proctal p, void *addr, const unsigned long *in, size_t size);
size_t proctal_write_longlong(proctal p, void *addr, long long in);
size_t proctal_write_longlong_array(proctal p, void *addr, const long long *in, size_t size);
size_t proctal_write_ulonglong(proctal p, void *addr, unsigned long long in);
size_t proctal_write_ulonglong_array(proctal p, void *addr, const unsigned long long *in, size_t size);
size_t proctal_write_float(proctal p, void *addr, float in);
size_t proctal_write_float_array(proctal p, void *addr, const float *in, size_t size);
size_t proctal_write_double(proctal p, void *addr, double in);
size_t proctal_write_double_array(proctal p, void *addr, const double *in, size_t size);
size_t proctal_write_longdouble(proctal p, void *addr, long double in);
size_t proctal_write_longdouble_array(proctal p, void *addr, const long double *in, size_t size);
size_t proctal_write_address(proctal p, void *addr, void *in);
size_t proctal_write_address_array(proctal p, void *addr, const void **in, size_t size);

/*
 * Iterates over addresses in a process.
 *
 * How to create, configure and use the iterator is a quite elaborated process.
 * You must first call proctal_addr_iter_create which will return a handle to
 * an iterator. Regardless of succeeding or failing, you still have to destroy
 * it.
 *
 * After creating the iterator and before you start iterating, you can
 * configure options like the address alignment.
 *
 * To begin iterating, you call proctal_addr_iter_next and you do so repeatedly
 * to get the next address. It returns 1 on success and 0 when there are either
 * no more addresses to return or a failure has occurred. You will most likely
 * want to call this in a loop.
 *
 * Once you're done iterating, you can call proctal_addr_iter_destroy to declare
 * the iterator as garbage or call proctal_addr_iter_restart to get to the same
 * stage after the call to proctal_addr_iter_create while retaining the options
 * you've configured.
 *
 * Any function call can fail, so you should call proctal_error right after any
 * function call to check whether something went wrong.
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
 * Sets and returns whether to iterate over readable addresses.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_addr_iter_read(proctal_addr_iter iter);
void proctal_addr_iter_set_read(proctal_addr_iter iter, int read);

/*
 * Sets and returns whether to iterate over writable addresses.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 0.
 */
int proctal_addr_iter_write(proctal_addr_iter iter);
void proctal_addr_iter_set_write(proctal_addr_iter iter, int write);

/*
 * Sets and returns whether to iterate over executable addresses.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 0.
 */
int proctal_addr_iter_execute(proctal_addr_iter iter);
void proctal_addr_iter_set_execute(proctal_addr_iter iter, int execute);

/*
 * Freezes and unfreezes main thread of execution.
 *
 * You should unfreeze before destroying or exiting your program otherwise it
 * will cause undefined behavior.
 */
int proctal_freeze(proctal p);
int proctal_unfreeze(proctal p);

/*
 * Watches for accesses at a defined address by the main execution thread.
 *
 * You start by calling proctal_watch_create to create a watch handle. You
 * should check if the watch handle successfully created by calling
 * proctal_error.
 *
 * You can define the address you want to watch by calling
 * proctal_watch_set_addr.
 *
 * You can set whether you want to watch for reads or writes by calling
 * proctal_watch_set_read and proctal_watch_set_write.
 *
 * Once the watch handler is configured, you can call proctal_watch_next which
 * will block until an access is made. After the first call, you may no longer
 * configure it any further.
 *
 * Once you're done using the handle, you must call proctal_watch_destroy to
 * release it.
 */
proctal_watch proctal_watch_create(proctal p);
int proctal_watch_next(proctal_watch pw, void **addr);
void proctal_watch_destroy(proctal_watch pw);

/*
 * Sets and gets the address to watch.
 */
void *proctal_watch_addr(proctal_watch pw);
void proctal_watch_set_addr(proctal_watch pw, void *addr);

/*
 * Sets and gets whether to watch for reads.
 *
 * A value of 1 means yes, 0 means no.
 */
int proctal_watch_read(proctal_watch pw);
void proctal_watch_set_read(proctal_watch pw, int r);

/*
 * Sets and gets whether to watch for writes.
 *
 * A value of 1 means yes, 0 means no.
 */
int proctal_watch_write(proctal_watch pw);
void proctal_watch_set_write(proctal_watch pw, int w);

/*
 * Sets and gets whether to watch for instruction execution.
 *
 * A value of 1 means yes, 0 means no.
 */
int proctal_watch_execute(proctal_watch pw);
void proctal_watch_set_execute(proctal_watch pw, int x);

/*
 * Executes arbitrary code.
 *
 * You need to pass a pointer to byte code. It will be embedded at some place
 * in memory and execution will jump directly to there, leaving registers and
 * stack intact.
 *
 * On failure returns 0.
 */
int proctal_execute(proctal p, const char *byte_code, size_t byte_code_length);

/*
 * Allocates memory in the process.
 *
 * The size parameter specifies the minimum number of bytes. It may allocate
 * more space but you should never rely on that.
 * The perm parameter specifies read, write and execute permissions. You can
 * OR the macros whose name start with PROCTAL_ALLOC_PERM.
 *
 * On success it returns the start address. On failure it will return NULL and
 * proctal_error will return an error code.
 */
void *proctal_alloc(proctal p, size_t size, int perm);

/*
 * Deallocates memory allocated by proctal_malloc.
 *
 * This command is special in that it can deallocate memory allocated by a
 * different instance of Proctal.
 *
 * Behavior is left undefined if you deallocate memory that had already been
 * deallocated.
 */
void proctal_dealloc(proctal p, void *addr);

/*
 * Sets the memory allocator/deallocator used for internal data structures.
 *
 * These functions should only be called right after creating an instance of
 * Proctal to avoid having the wrong deallocator being called on an internal
 * data structure that was allocated before you changed it.
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
