#ifndef PROCTAL_H
#define PROCTAL_H

/*
 * Include statements that contain type definitions used in the following
 * function declarations. They are included here for your convenience to allow
 * you to include this header file without having to worry about what you'd
 * need to include beforehand.
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
#define PROCTAL_ERROR_INJECTION_LOCATION_NOT_FOUND 14
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
 * Definition of a handle. This object is used to keep track of state. It's
 * nothing more than an opaque pointer.
 */
typedef struct proctal *proctal_t;

/*
 * Creates a handle.
 *
 * This would be the first function you'd want to call.
 *
 * A new handle has its state set to default values.
 *
 * When you're done using the handle, you need to pass it to the proctal_close
 * function to destroy it.
 *
 * This function may fail such as when the system is running out of memory. See
 * the description for the proctal_error function on how to deal with errors.
 *
 * Using a handle that was not successfully created results in undefined
 * behavior.
 */
proctal_t proctal_open(void);

/*
 * Destroys a handle.
 *
 * This would be the last function you'd want to call.
 */
void proctal_close(proctal_t p);

/*
 * Allows you to check if an error has happened with the given handle.
 *
 * Any non-zero value that is returned is an error code. Error codes have a
 * corresponding macro definition whose names start with PROCTAL_ERROR. A 0
 * return value means there is no error
 *
 * You can call proctal_error_recover to try to recover from an error.
 *
 * Keep in mind that using a handle without recovering from an error results in
 * undefined behavior.
 */
int proctal_error(proctal_t p);

/*
 * Attempts to recover from an error.
 *
 * Returns 1 on success and 0 on failure.
 *
 * On success, the error code is cleared for the given handle, making it usable
 * like normal again.
 *
 * On failure, the handle is deemed unusable and must be destroyed.
 *
 * If the handle has no error, this function will do nothing and report that it
 * succeeded.
 */
int proctal_error_recover(proctal_t p);

/*
 * Similar to proctal_error, but returns pointers to read-only C-style strings
 * for diagnostic purposes such as logging. NULL is returned to indicate no
 * error.
 *
 * These messages are in English and are not suitable for displaying to the
 * user.
 */
const char *proctal_error_message(proctal_t p);

/*
 * Sets which program you want to access.
 *
 * On Linux you must pass a PID (Process ID).
 */
void proctal_pid_set(proctal_t p, int pid);

/*
 * Returns the id of the program that is being accessed.
 *
 * On Linux this would be a PID (Process ID).
 *
 * This will return 0 if you have never set an id.
 */
int proctal_pid(proctal_t p);

/*
 * Reads a given number of bytes (size) starting from the given address
 * (address).
 *
 * This function assumes it can safely write the same number of bytes to the
 * given buffer (out).
 *
 * Will return the number of bytes it successfully read.
 *
 * Not returning the same number of bytes that were given indicates an error.
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
size_t proctal_read(proctal_t p, void *address, void *out, size_t size);

size_t proctal_read_char(proctal_t p, void *address, char *out);

size_t proctal_read_char_array(proctal_t p, void *address, char *out, size_t size);

size_t proctal_read_signed_char(proctal_t p, void *address, signed char *out);

size_t proctal_read_signed_char_array(proctal_t p, void *address, signed char *out, size_t size);

size_t proctal_read_unsigned_char(proctal_t p, void *address, unsigned char *out);

size_t proctal_read_unsigned_char_array(proctal_t p, void *address, unsigned char *out, size_t size);

size_t proctal_read_short(proctal_t p, void *address, short *out);

size_t proctal_read_short_array(proctal_t p, void *address, short *out, size_t size);

size_t proctal_read_unsigned_short(proctal_t p, void *address, unsigned short *out);

size_t proctal_read_unsigned_short_array(proctal_t p, void *address, unsigned short *out, size_t size);

size_t proctal_read_int(proctal_t p, void *address, int *out);

size_t proctal_read_int_array(proctal_t p, void *address, int *out, size_t size);

size_t proctal_read_unsigned_int(proctal_t p, void *address, unsigned int *out);

size_t proctal_read_unsigned_int_array(proctal_t p, void *address, unsigned int *out, size_t size);

size_t proctal_read_long(proctal_t p, void *address, long *out);

size_t proctal_read_long_array(proctal_t p, void *address, long *out, size_t size);

size_t proctal_read_unsigned_long(proctal_t p, void *address, unsigned long *out);

size_t proctal_read_unsigned_long_array(proctal_t p, void *address, unsigned long *out, size_t size);

size_t proctal_read_long_long(proctal_t p, void *address, long long *out);

size_t proctal_read_long_long_array(proctal_t p, void *address, long long *out, size_t size);

size_t proctal_read_unsigned_long_long(proctal_t p, void *address, unsigned long long *out);

size_t proctal_read_unsigned_long_long_array(proctal_t p, void *address, unsigned long long *out, size_t size);

size_t proctal_read_float(proctal_t p, void *address, float *out);

size_t proctal_read_float_array(proctal_t p, void *address, float *out, size_t size);

size_t proctal_read_double(proctal_t p, void *address, double *out);

size_t proctal_read_double_array(proctal_t p, void *address, double *out, size_t size);

size_t proctal_read_long_double(proctal_t p, void *address, long double *out);

size_t proctal_read_long_double_array(proctal_t p, void *address, long double *out, size_t size);

size_t proctal_read_address(proctal_t p, void *address, void **out);

size_t proctal_read_address_array(proctal_t p, void *address, void **out, size_t size);

/*
 * Writes a given number of bytes (size) to the given address (address).
 *
 * This function assumes it can safely read the same number of bytes from the
 * given buffer (in).
 *
 * Will return the number of bytes it successfully wrote.
 *
 * Not returning the same number of bytes that were given indicates an error.
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
size_t proctal_write(proctal_t p, void *address, const void *in, size_t size);

size_t proctal_write_char(proctal_t p, void *address, char in);

size_t proctal_write_char_array(proctal_t p, void *address, const char *in, size_t size);

size_t proctal_write_signed_char(proctal_t p, void *address, signed char in);

size_t proctal_write_signed_char_array(proctal_t p, void *address, const signed char *in, size_t size);

size_t proctal_write_unsigned_char(proctal_t p, void *address, unsigned char in);

size_t proctal_write_unsigned_char_array(proctal_t p, void *address, const unsigned char *in, size_t size);

size_t proctal_write_short(proctal_t p, void *address, short in);

size_t proctal_write_short_array(proctal_t p, void *address, const short *in, size_t size);

size_t proctal_write_unsigned_short(proctal_t p, void *address, unsigned short in);

size_t proctal_write_unsigned_short_array(proctal_t p, void *address, const unsigned short *in, size_t size);

size_t proctal_write_int(proctal_t p, void *address, int in);

size_t proctal_write_int_array(proctal_t p, void *address, const int *in, size_t size);

size_t proctal_write_unsigned_int(proctal_t p, void *address, unsigned int in);

size_t proctal_write_unsigned_int_array(proctal_t p, void *address, const unsigned int *in, size_t size);

size_t proctal_write_long(proctal_t p, void *address, long in);

size_t proctal_write_long_array(proctal_t p, void *address, const long *in, size_t size);

size_t proctal_write_unsigned_long(proctal_t p, void *address, unsigned long in);

size_t proctal_write_unsigned_long_array(proctal_t p, void *address, const unsigned long *in, size_t size);

size_t proctal_write_long_long(proctal_t p, void *address, long long in);

size_t proctal_write_long_long_array(proctal_t p, void *address, const long long *in, size_t size);

size_t proctal_write_unsigned_long_long(proctal_t p, void *address, unsigned long long in);

size_t proctal_write_unsigned_long_long_array(proctal_t p, void *address, const unsigned long long *in, size_t size);

size_t proctal_write_float(proctal_t p, void *address, float in);

size_t proctal_write_float_array(proctal_t p, void *address, const float *in, size_t size);

size_t proctal_write_double(proctal_t p, void *address, double in);

size_t proctal_write_double_array(proctal_t p, void *address, const double *in, size_t size);

size_t proctal_write_long_double(proctal_t p, void *address, long double in);

size_t proctal_write_long_double_array(proctal_t p, void *address, const long double *in, size_t size);

size_t proctal_write_address(proctal_t p, void *address, void *in);

size_t proctal_write_address_array(proctal_t p, void *address, const void **in, size_t size);

/*
 * Starts scanning for addresses.
 *
 * When you're done scanning, you must call proctal_scan_address_stop.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_scan_address_start(proctal_t p);

/*
 * Stops scanning for addresses.
 *
 * You must have previously called proctal_scan_address_start, otherwise
 * behavior is undefined.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_scan_address_stop(proctal_t p);

/*
 * After proctal_scan_address_start is called, calling this function allows you
 * to retrieve an address.
 *
 * It will return 1 on success, 0 on failure or when there are no more
 * addresses.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
int proctal_scan_address_next(proctal_t p, void **address);

/*
 * Returns the alignment requirement of the addresses.
 *
 * The default value is 1.
 */
size_t proctal_scan_address_align(proctal_t p);

/*
 * Sets the alignment requirement of the addresses.
 *
 * If you try to pass 0 it will be treated as 1.
 *
 * You should only call this function before proctal_scan_address_start.
 */
void proctal_scan_address_align_set(proctal_t p, size_t align);

/*
 * Returns the size that the addresses can be dereferenced up to.
 *
 * The default value is 1.
 */
size_t proctal_scan_address_size(proctal_t p);

/*
 * Sets the size that the addresses can be dereferenced up to.
 *
 * This can prevent the scanner from returning you an address that is not
 * suitable for storing a value of a certain size.
 *
 * You should only call this function before proctal_scan_address_start.
 */
void proctal_scan_address_size_set(proctal_t p, size_t size);

/*
 * Returns which memory regions to scan over.
 *
 * The default value is 0.
 */
long proctal_scan_address_region(proctal_t p);

/*
 * Sets which memory regions to scan over.
 *
 * Setting the mask to 0 will let the scanner go over all memory regions.
 *
 * You should only call this function before proctal_scan_address_start.
 */
void proctal_scan_address_region_set(proctal_t p, long mask);

/*
 * Checks whether to scan addresses marked as readable by the operating system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_scan_address_read(proctal_t p);

/*
 * Sets whether to scan addresses marked as readable by the operating system.
 *
 * 1 means yes, 0 means no.
 *
 * You should only call this function before proctal_scan_address_start.
 */
void proctal_scan_address_read_set(proctal_t p, int read);

/*
 * Checks whether to scan addresses marked as writable by the operating system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_scan_address_write(proctal_t p);

/*
 * Sets whether to scan addresses marked as writable by the operating system.
 *
 * 1 means yes, 0 means no.
 *
 * You should only call this function before proctal_scan_address_start.
 */
void proctal_scan_address_write_set(proctal_t p, int write);

/*
 * Checks whether to scan addresses marked as executable by the operating system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_scan_address_execute(proctal_t p);

/*
 * Sets whether to scan addresses marked as executable by the operating system.
 *
 * 1 means yes, 0 means no.
 *
 * You should only call this function before proctal_scan_address_start.
 */
void proctal_scan_address_execute_set(proctal_t p, int execute);

/*
 * Starts scanning for memory regions.
 *
 * When you're done scanning, you must call proctal_scan_region_stop.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_scan_region_start(proctal_t p);

/*
 * Stops scanning for memory regions.
 *
 * You must have previously called proctal_scan_region_start, otherwise
 * behavior is undefined.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_scan_region_stop(proctal_t p);

/*
 * After proctal_scan_region_start is called, calling this function allows you
 * to retrieve the addresses of the start and the end of a memory region.
 *
 * It will return 1 on success, 0 on failure or when there are no more memory
 * regions.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
int proctal_scan_region_next(proctal_t p, void **start, void **end);

/*
 * Returns which memory regions to scan over.
 *
 * The default value is 0.
 */
long proctal_scan_region_mask(proctal_t p);

/*
 * Sets which memory regions to scan over.
 *
 * Setting the mask to 0 will let the scanner go over all memory regions.
 *
 * You should only call this function before proctal_scan_region_start.
 */
void proctal_scan_region_mask_set(proctal_t p, long mask);

/*
 * Checks whether to scan memory regions marked as readable by the operating
 * system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_scan_region_read(proctal_t p);

/*
 * Sets whether to scan memory regions marked as readable by the operating
 * system.
 *
 * 1 means yes, 0 means no.
 *
 * You should only call this function before proctal_scan_region_start.
 */
void proctal_scan_region_read_set(proctal_t p, int read);

/*
 * Checks whether to scan memory regions marked as writable by the operating
 * system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_scan_region_write(proctal_t p);

/*
 * Sets whether to scan memory regions marked as writable by the operating
 * system.
 *
 * 1 means yes, 0 means no.
 *
 * You should only call this function before proctal_scan_region_start.
 */
void proctal_scan_region_write_set(proctal_t p, int write);

/*
 * Checks whether to scan memory regions marked as executable by the operating
 * system.
 *
 * 1 means yes, 0 means no.
 *
 * By default this is set to 1.
 */
int proctal_scan_region_execute(proctal_t p);

/*
 * Sets whether to scan memory regions marked as executable by the operating
 * system.
 *
 * 1 means yes, 0 means no.
 *
 * You should only call this function before proctal_scan_region_start.
 */
void proctal_scan_region_execute_set(proctal_t p, int execute);

/*
 * Freezes program execution.
 *
 * Freezing twice results in undefined behavior.
 *
 * You can unfreeze again by calling proctal_unfreeze.
 *
 * Closing the handle without unfreezing first results in undefined behavior.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_freeze(proctal_t p);

/*
 * Unfreezes execution.
 *
 * You can only call this function if you had previously called proctal_freeze,
 * otherwise behavior is undefined.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_unfreeze(proctal_t p);

/*
 * Starts watching for memory accesses.
 *
 * You can define the address you want to watch by calling
 * proctal_watch_address_set.
 *
 * You can set whether you want to watch for reads, writes and execution by
 * calling proctal_watch_read_set, proctal_watch_write_set and
 * proctal_watch_execute_set, respectively.
 *
 * When the memory address is accessed the thread of execution will be paused
 * until either proctal_watch or proctal_watch_stop are called.
 *
 * To stop watching, you must call proctal_watch_stop.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_watch_start(proctal_t p);

/*
 * Stops watching the memory address.
 *
 * You must have previously called proctal_watch_start successfully otherwise
 * behavior is left undefined.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_watch_stop(proctal_t p);

/*
 * After proctal_watch_start is called, you will want to call this function to
 * check if the memory address was accessed.
 *
 * If a memory access was detected, it will return 1 and write out the address.
 * If no memory access was detected, it will return 0. On failure it will also
 * return 0. See the description for the proctal_error function on how to deal
 * with errors.
 *
 * You must have previously called proctal_watch_start successfully otherwise
 * behavior is left undefined.
 */
int proctal_watch_next(proctal_t p, void **address);

/*
 * Returns the address that will be watched for accesses.
 */
void *proctal_watch_address(proctal_t p);

/*
 * Sets the address to watch.
 *
 * You should only call this function before proctal_watch_start.
 */
void proctal_watch_address_set(proctal_t p, void *address);

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
 *
 * You should only call this function before proctal_watch_start.
 */
void proctal_watch_read_set(proctal_t p, int read);

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
 *
 * You should only call this function before proctal_watch_start.
 */
void proctal_watch_write_set(proctal_t p, int write);

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
 *
 * You should only call this function before proctal_watch_start.
 */
void proctal_watch_execute_set(proctal_t p, int execute);

/*
 * Executes arbitrary code.
 *
 * The code will be executed in the context of the main thread.
 *
 * You need to pass a pointer to your bytecode and its length. It will be
 * embedded at some place in memory and executed in a new stack frame. Your
 * code is free to modify any registers because they will be restored to their
 * original values on return. You can either use a return instruction to
 * explicitly return or let the processor continue executing after the last
 * instruction you gave.
 *
 * The instructions cannot rely on where they will be placed in memory.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_execute(proctal_t p, const void *bytecode, size_t bytecode_length);

/*
 * Allocates memory.
 *
 * The size parameter specifies the number of bytes you're interested in
 * allocating. It may allocate more space but you should never rely on that.
 *
 * Access permissions can be set by calling proctal_allocate_read_set,
 * proctal_allocate_write_set and proctal_allocate_execute_set beforehand.
 *
 * On success it returns the start address. On failure it will return NULL. See
 * the description for the proctal_error function on how to deal with errors.
 */
void *proctal_allocate(proctal_t p, size_t size);

/*
 * Checks whether read permission is set.
 *
 * 1 means yes, 0 means no.
 *
 * The default value is 1.
 */
int proctal_allocate_read(proctal_t p);

/*
 * Sets whether read permission is set.
 *
 * 1 means yes, 0 means no.
 */
void proctal_allocate_read_set(proctal_t p, int read);

/*
 * Checks whether write permission is set.
 *
 * 1 means yes, 0 means no.
 *
 * The default value is 1.
 */
int proctal_allocate_write(proctal_t p);

/*
 * Sets whether write permission is set.
 *
 * 1 means yes, 0 means no.
 */
void proctal_allocate_write_set(proctal_t p, int write);

/*
 * Checks whether execute permission is set.
 *
 * 1 means yes, 0 means no.
 *
 * The default value is 1.
 */
int proctal_allocate_execute(proctal_t p);

/*
 * Sets whether execute permission is set.
 *
 * 1 means yes, 0 means no.
 */
void proctal_allocate_execute_set(proctal_t p, int execute);

/*
 * Deallocates memory allocated by proctal_allocate.
 *
 * This command is special in that it can deallocate memory allocated by a
 * different handle, even from a different task.
 *
 * Behavior is left undefined if you deallocate memory that had already been
 * deallocated.
 *
 * See the description for the proctal_error function on how to deal with
 * errors.
 */
void proctal_deallocate(proctal_t p, void *address);

/*
 * Sets the memory allocator that will be used for internal data structures.
 *
 * If never called or passed NULL, will use the version of malloc that the
 * library was linked to.
 *
 * This function must be called before any other function of the library so as
 * to avoid having a deallocator being called with an address returned by the
 * incorrect allocator pair.
 */
void proctal_malloc_set(void *(*malloc)(size_t));

/*
 * Sets the memory deallocator that will be used for internal data structures.
 *
 * If never called or passed NULL, will use the version of free that the
 * library was linked to.
 *
 * This function must be called before any other function of the library so as
 * to avoid having a deallocator being called with an address returned by the
 * incorrect allocator pair.
 */
void proctal_free_set(void (*free)(void *));

/*
 * Returns the version number.
 */
unsigned int proctal_version(void);

#endif /* PROCTAL_H */
