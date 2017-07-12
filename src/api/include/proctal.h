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
#define PROCTAL_ERROR_PROGRAM_NOT_FOUND 12
#define PROCTAL_ERROR_PROGRAM_NOT_SET 13
#define PROCTAL_ERROR_INJECT_ADDR_NOT_FOUND 14
#define PROCTAL_ERROR_PROGRAM_SEGFAULT 15
#define PROCTAL_ERROR_PROGRAM_EXITED 16
#define PROCTAL_ERROR_PROGRAM_STOPPED 17
#define PROCTAL_ERROR_PROGRAM_UNTAMEABLE 18
#define PROCTAL_ERROR_PROGRAM_TRAPPED 19
#define PROCTAL_ERROR_INTERRUPT 20
#define PROCTAL_ERROR_PROGRAM_INTERRUPT 21

/*
 * Macro definitions of known memory regions.
 */
#define PROCTAL_REGION_STACK 1
#define PROCTAL_REGION_HEAP 2
#define PROCTAL_REGION_PROGRAM_CODE 4

/*
 * Macro definitions of memory allocation permissions.
 */
#define PROCTAL_ALLOCATE_PERM_EXECUTE 1
#define PROCTAL_ALLOCATE_PERM_WRITE 2
#define PROCTAL_ALLOCATE_PERM_READ 4

/*
 * Provides a type name for a handle. The actual definition is an
 * implementation detail that you shouldn't worry about.
 */
typedef struct proctal *proctal_t;

/*
 * Creates a handle.
 *
 * This would be the first function you'd want to call. Most functions operate
 * on a handle.
 *
 * There is always a tiny chance that this call may fail such as when the
 * system is running out of memory therefore you should call proctal_error
 * right after. And regardless of it succeeding or failing you still need to
 * call proctal_close.
 *
 * Using a handle that failed to be created correctly will result in undefined
 * behavior, likely leading to a crash.
 */
proctal_t proctal_open(void);

/*
 * Destroys a handle.
 *
 * This is definitely the last function you'd call.
 */
void proctal_close(proctal_t p);

/*
 * Allows you to check if an error happened with the given handle.
 *
 * Any non-zero value that is returned is an error code. Error codes are
 * defined as macros whose name start with PROCTAL_ERROR. A 0 return value
 * means there is no error.
 *
 * This function will keep reporting the same error until you acknowledge it
 * with a call to proctal_error_ack.
 */
int proctal_error(proctal_t p);

/*
 * Acknowledge the error that occurred with the given handle.
 *
 * This function will do nothing if the given handle has no error.
 */
void proctal_error_ack(proctal_t p);

/*
 * Similar to proctal_error, but returns pointers to read-only C-style strings
 * for diagnostic purposes such as logging. NULL is returned to indicate no
 * error.
 *
 * These messages are in English and are not suitable for displaying to the
 * user.
 */
const char *proctal_error_msg(proctal_t p);

/*
 * Sets which program you want to access.
 *
 * On Linux you must pass a PID (Process ID).
 */
void proctal_set_pid(proctal_t p, int pid);

/*
 * Returns the id of the program.
 *
 * On Linux this would be a PID (Process ID).
 *
 * This will return 0 if you have never set the id.
 */
int proctal_pid(proctal_t p);

/*
 * Reads a specified length of characters starting from the given address. This
 * function assumes it can safely write the same length to the given buffer.
 *
 * Will return the number of characters it successfuly reads.
 *
 * Not returning the same length indicates an error. Call proctal_error to find
 * out what happened.
 *
 * There are also convenience functions for reading native C types where length
 * corresponds to the type's size and the return value is the the number of
 * values read instead of the actual length.
 */
size_t proctal_read(proctal_t p, void *addr, char *out, size_t size);
size_t proctal_read_char(proctal_t p, void *addr, char *out);
size_t proctal_read_char_array(proctal_t p, void *addr, char *out, size_t size);
size_t proctal_read_signed_char(proctal_t p, void *addr, signed char *out);
size_t proctal_read_signed_char_array(proctal_t p, void *addr, signed char *out, size_t size);
size_t proctal_read_unsigned_char(proctal_t p, void *addr, unsigned char *out);
size_t proctal_read_unsigned_char_array(proctal_t p, void *addr, unsigned char *out, size_t size);
size_t proctal_read_short(proctal_t p, void *addr, short *out);
size_t proctal_read_short_array(proctal_t p, void *addr, short *out, size_t size);
size_t proctal_read_unsigned_short(proctal_t p, void *addr, unsigned short *out);
size_t proctal_read_unsigned_short_array(proctal_t p, void *addr, unsigned short *out, size_t size);
size_t proctal_read_int(proctal_t p, void *addr, int *out);
size_t proctal_read_int_array(proctal_t p, void *addr, int *out, size_t size);
size_t proctal_read_unsigned_int(proctal_t p, void *addr, unsigned int *out);
size_t proctal_read_unsigned_int_array(proctal_t p, void *addr, unsigned int *out, size_t size);
size_t proctal_read_long(proctal_t p, void *addr, long *out);
size_t proctal_read_long_array(proctal_t p, void *addr, long *out, size_t size);
size_t proctal_read_unsigned_long(proctal_t p, void *addr, unsigned long *out);
size_t proctal_read_unsigned_long_array(proctal_t p, void *addr, unsigned long *out, size_t size);
size_t proctal_read_long_long(proctal_t p, void *addr, long long *out);
size_t proctal_read_long_long_array(proctal_t p, void *addr, long long *out, size_t size);
size_t proctal_read_unsigned_long_long(proctal_t p, void *addr, unsigned long long *out);
size_t proctal_read_unsigned_long_long_array(proctal_t p, void *addr, unsigned long long *out, size_t size);
size_t proctal_read_float(proctal_t p, void *addr, float *out);
size_t proctal_read_float_array(proctal_t p, void *addr, float *out, size_t size);
size_t proctal_read_double(proctal_t p, void *addr, double *out);
size_t proctal_read_double_array(proctal_t p, void *addr, double *out, size_t size);
size_t proctal_read_long_double(proctal_t p, void *addr, long double *out);
size_t proctal_read_long_double_array(proctal_t p, void *addr, long double *out, size_t size);
size_t proctal_read_address(proctal_t p, void *addr, void **out);
size_t proctal_read_address_array(proctal_t p, void *addr, void **out, size_t size);

/*
 * Writes a specified length of characters starting from an address. This
 * function assumes it can safely read the same length from the given buffer.
 *
 * Will return the number of characters it successfuly writes.
 *
 * Not returning the same length indicates an error. Call proctal_error to find
 * out what happened.
 *
 * There are also convenience functions for writing native C types where length
 * corresponds to the type's size and the return value is the the number of
 * values written instead of the actual length.
 */
size_t proctal_write(proctal_t p, void *addr, const char *in, size_t size);
size_t proctal_write_char(proctal_t p, void *addr, char in);
size_t proctal_write_char_array(proctal_t p, void *addr, const char *in, size_t size);
size_t proctal_write_signed_char(proctal_t p, void *addr, signed char in);
size_t proctal_write_signed_char_array(proctal_t p, void *addr, const signed char *in, size_t size);
size_t proctal_write_unsigned_char(proctal_t p, void *addr, unsigned char in);
size_t proctal_write_unsigned_char_array(proctal_t p, void *addr, const unsigned char *in, size_t size);
size_t proctal_write_short(proctal_t p, void *addr, short in);
size_t proctal_write_short_array(proctal_t p, void *addr, const short *in, size_t size);
size_t proctal_write_unsigned_short(proctal_t p, void *addr, unsigned short in);
size_t proctal_write_unsigned_short_array(proctal_t p, void *addr, const unsigned short *in, size_t size);
size_t proctal_write_int(proctal_t p, void *addr, int in);
size_t proctal_write_int_array(proctal_t p, void *addr, const int *in, size_t size);
size_t proctal_write_unsigned_int(proctal_t p, void *addr, unsigned int in);
size_t proctal_write_unsigned_int_array(proctal_t p, void *addr, const unsigned int *in, size_t size);
size_t proctal_write_long(proctal_t p, void *addr, long in);
size_t proctal_write_long_array(proctal_t p, void *addr, const long *in, size_t size);
size_t proctal_write_unsigned_long(proctal_t p, void *addr, unsigned long in);
size_t proctal_write_unsigned_long_array(proctal_t p, void *addr, const unsigned long *in, size_t size);
size_t proctal_write_long_long(proctal_t p, void *addr, long long in);
size_t proctal_write_long_long_array(proctal_t p, void *addr, const long long *in, size_t size);
size_t proctal_write_unsigned_long_long(proctal_t p, void *addr, unsigned long long in);
size_t proctal_write_unsigned_long_long_array(proctal_t p, void *addr, const unsigned long long *in, size_t size);
size_t proctal_write_float(proctal_t p, void *addr, float in);
size_t proctal_write_float_array(proctal_t p, void *addr, const float *in, size_t size);
size_t proctal_write_double(proctal_t p, void *addr, double in);
size_t proctal_write_double_array(proctal_t p, void *addr, const double *in, size_t size);
size_t proctal_write_long_double(proctal_t p, void *addr, long double in);
size_t proctal_write_long_double_array(proctal_t p, void *addr, const long double *in, size_t size);
size_t proctal_write_address(proctal_t p, void *addr, void *in);
size_t proctal_write_address_array(proctal_t p, void *addr, const void **in, size_t size);

/*
 * Puts the address iterator in a clean state.
 *
 * You will want to call this function whenever you begin iterating over
 * addresses to make sure you're starting from the first.
 *
 * It will do nothing if the address iterator is already in a clean state.
 */
void proctal_address_new(proctal_t p);

/*
 * Iterates over the entire address space.
 *
 * Any time you call this function it will pass you a different address unless
 * it fails or has ran out of addresses.
 *
 * It will return 1 when it passes an address, 0 on failure or when it has ran
 * out of addresses.
 *
 * You should call proctal_error to verify if 0 meant failure.
 */
int proctal_address(proctal_t p, void **addr);

/*
 * Returns the alignment requirements of the addresses you're iterating over.
 *
 * The default value is 1.
 */
size_t proctal_address_align(proctal_t p);

/*
 * Sets the alignment requirements of the addresses you want to iterate over.
 *
 * If you try to pass 0 it will be treated as 1.
 *
 * This call should follow proctal_address_new.
 */
void proctal_address_set_align(proctal_t p, size_t align);

/*
 * Returns the size of the values pointed by the addresses you're iterating
 * over.
 *
 * The default value is 1.
 */
size_t proctal_address_size(proctal_t p);

/*
 * Sets the size of the values pointed by the addresses you want to iterate
 * over.
 *
 * This can prevent the iterator from returning you an address that is not
 * suitable for storing a value of a certain size.
 *
 * This call should follow proctal_address_new.
 */
void proctal_address_set_size(proctal_t p, size_t size);

/*
 * Returns which memory regions the addresses iterated could belong to.
 *
 * The default value is 0.
 */
long proctal_address_region(proctal_t p);

/*
 * Sets which memory regions the addresses to iterate belong to.
 *
 * Setting the mask to 0 will let the iterator go over all memory regions.
 *
 * This call should follow proctal_address_new.
 */
void proctal_address_set_region(proctal_t p, long mask);

/*
 * Checks whether it's iterating over addresses marked as readable by the
 * operating system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_address_read(proctal_t p);

/*
 * Sets whether to iterate over addresses marked as readable by the operating
 * system.
 *
 * 1 means yes, 0 means no.
 *
 * This call should follow proctal_address_new.
 */
void proctal_address_set_read(proctal_t p, int read);

/*
 * Checks whether it's iterating over addresses marked as writable by the
 * operating system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_address_write(proctal_t p);

/*
 * Sets whether to iterate over addresses marked as writable by the operating
 * system.
 *
 * 1 means yes, 0 means no.
 *
 * This call should follow proctal_address_new.
 */
void proctal_address_set_write(proctal_t p, int write);

/*
 * Checks whether it's iterating over addresses marked as executable by the
 * operating system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_address_execute(proctal_t p);

/*
 * Sets whether to iterate over addresses marked as executable by the operating
 * system.
 *
 * 1 means yes, 0 means no.
 *
 * This call should follow proctal_address_new.
 */
void proctal_address_set_execute(proctal_t p, int execute);

/*
 * Puts the memory region iterator in a clean state.
 *
 * You will want to call this function whenever you begin iterating over
 * memory regions to make sure you're starting from the first.
 *
 * It will do nothing if the memory region iterator is already in a clean
 * state.
 */
void proctal_region_new(proctal_t p);

/*
 * Iterates over the entire address space by memory regions.
 *
 * Any time you call this function it will pass you the starting and ending
 * address of a memory region unless it fails or has iterated over all.
 *
 * It will return 1 on success, 0 on failure or when it has iterated over all
 * memory regions.
 *
 * You should call proctal_error to verify if 0 meant failure.
 */
int proctal_region(proctal_t p, void **start, void **end);

/*
 * Returns which memory regions are being iterated over.
 *
 * The default value is 0.
 */
long proctal_region_mask(proctal_t p);

/*
 * Sets which memory regions are going to be iterated over.
 *
 * Setting the mask to 0 will let the iterator go over all memory regions.
 *
 * This call should follow proctal_region_new.
 */
void proctal_region_set_mask(proctal_t p, long mask);

/*
 * Checks whether it's iterating over memory regions marked as readable by the
 * operating system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_region_read(proctal_t p);

/*
 * Sets whether to iterate over memory regions marked as readable by the
 * operating system.
 *
 * 1 means yes, 0 means no.
 *
 * This call should follow proctal_region_new.
 */
void proctal_region_set_read(proctal_t p, int read);

/*
 * Checks whether it's iterating over memory regions marked as writable by the
 * operating system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_region_write(proctal_t p);

/*
 * Sets whether to iterate over memory regions marked as writable by the
 * operating system.
 *
 * 1 means yes, 0 means no.
 *
 * This call should follow proctal_region_new.
 */
void proctal_region_set_write(proctal_t p, int write);

/*
 * Checks whether it's iterating over memory regions marked as executable by
 * the operating system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_region_execute(proctal_t p);

/*
 * Sets whether to iterate over memory regions marked as executable by the
 * operating system.
 *
 * 1 means yes, 0 means no.
 *
 * This call should follow proctal_region_new.
 */
void proctal_region_set_execute(proctal_t p, int execute);

/*
 * Freezes program execution.
 *
 * You should unfreeze before exiting your program otherwise something may
 * crash.
 *
 * Closing the handle automatically unfreezes.
 */
int proctal_freeze(proctal_t p);

/*
 * Unfreezes execution.
 *
 * You may only unfreeze as many times as you have frozen otherwise behavior is
 * left undefined.
 */
int proctal_unfreeze(proctal_t p);

/*
 * Starts watching for memory accesses.
 *
 * You can define the address you want to watch by calling
 * proctal_watch_set_address.
 *
 * You can set whether you want to watch for reads, writes and execution by
 * calling proctal_watch_set_read, proctal_watch_set_write and
 * proctal_watch_set_execute, respectively.
 *
 * When the memory address is accessed the thread of execution will be paused
 * until either proctal_watch or proctal_watch_stop are called.
 *
 * On success it will return 1 and on failure it will return 0. Call
 * proctal_error to find out what went wrong.
 *
 * To stop watching, you must call proctal_watch_stop.
 */
int proctal_watch_start(proctal_t p);

/*
 * Stops watching the memory address.
 *
 * You must have previously called proctal_watch_start successfully otherwise
 * behavior is left undefined.
 */
void proctal_watch_stop(proctal_t p);

/*
 * After proctal_watch_start is called, you will want to call this function to
 * check if the memory address was accessed.
 *
 * On success it will return
 *
 * You must have previously called proctal_watch_start successfully otherwise
 * behavior is left undefined.
 */
int proctal_watch(proctal_t p, void **addr);

/*
 * Returns the address that will be watched for accesses.
 */
void *proctal_watch_address(proctal_t p);

/*
 * Sets the address to watch.
 */
void proctal_watch_set_address(proctal_t p, void *addr);

/*
 * Checks whether it's going to watch for reads.
 *
 * 1 means yes, 0 means no.
 *
 * The default value is 1.
 */
int proctal_watch_read(proctal_t p);

/*
 * Sets whether to watch for reads.
 *
 * 1 means yes, 0 means no.
 */
void proctal_watch_set_read(proctal_t p, int r);

/*
 * Checks whether it's going to watch for writes.
 *
 * 1 means yes, 0 means no.
 *
 * The default value is 1.
 */
int proctal_watch_write(proctal_t p);

/*
 * Sets whether to watch for writes.
 *
 * 1 means yes, 0 means no.
 */
void proctal_watch_set_write(proctal_t p, int w);

/*
 * Checks whether it's going to watch for execution.
 *
 * 1 means yes, 0 means no.
 *
 * The default value is 0.
 */
int proctal_watch_execute(proctal_t p);

/*
 * Sets whether to watch for execution.
 *
 * 1 means yes, 0 means no.
 */
void proctal_watch_set_execute(proctal_t p, int x);

/*
 * Executes arbitrary code.
 *
 * The code will be executed in the context of the main thread.
 *
 * You need to pass a pointer to your byte code and its length. It will be
 * embedded at some place in memory and executed in a new  stack frame. Your
 * code is free to modify any registers because they will be restored to their
 * original values on return. You can either use a return instruction to
 * explicitly return or let the processor continue executing after the last
 * instruction you gave.
 *
 * On failure returns 0. Call proctal_error to find out what happened.
 */
int proctal_execute(proctal_t p, const char *byte_code, size_t byte_code_length);

/*
 * Allocates memory.
 *
 * The size parameter specifies the number of bytes you're interested in
 * allocating. It may allocate more space but you should never rely on that.
 * The perm parameter specifies read, write and execute permissions. You can
 * OR the macros whose name start with PROCTAL_ALLOCATE_PERM.
 *
 * On success it returns the start address. On failure it will return NULL. You
 * can call proctal_error to find out what happened.
 */
void *proctal_allocate(proctal_t p, size_t size, int perm);

/*
 * Deallocates memory allocated by proctal_allocate.
 *
 * This command is special in that it can deallocate memory allocated by a
 * different handle.
 *
 * Behavior is left undefined if you deallocate memory that had already been
 * deallocated.
 */
void proctal_deallocate(proctal_t p, void *addr);

/*
 * Sets the memory allocator/deallocator used for internal data structures.
 *
 * These functions should only be called right after creating a handle to avoid
 * having the new deallocator being called on an internal data structure that
 * was allocated with the old allocator.
 */
void proctal_set_malloc(proctal_t p, void *(*malloc)(size_t));
void proctal_set_free(proctal_t p, void (*free)(void *));

/*
 * Global counterparts. These define the values that are used by default when
 * a handle is created.
 *
 * If never called or passed NULL, will use the version of malloc/free that the
 * library was linked to.
 *
 * These functions must be called before any other function of the library so
 * as to avoid having a deallocator being called with an address returned by
 * the incorrect allocator pair.
 */
void proctal_global_set_malloc(void *(*malloc)(size_t));
void proctal_global_set_free(void (*free)(void *));

#endif /* PROCTAL_H */
