#ifndef PROCTAL_H
#define PROCTAL_H

#include <stddef.h>
#include <sys/types.h>

typedef struct proctal_search_state *proctal_search_state;
typedef struct proctal_search_options *proctal_search_options;

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
 * Searches for values in the address space of a process.
 *
 * You need to:
 *     - Pass the Process ID of the running program.
 *     - A search state object. This keeps track of the progress. Call
 *     proctal_search_state_create() for a fresh state. Don't forget to call
 *     proctal_search_state_delete() when you're finished.
 *     - A search options object. This is what tells the function which values
 *     you're looking for. Call proctal_search_options_create() and then the
 *     filter methods you're interested in. Don't forget to call
 *     proctal_search_options_delete() when you're done.
 *     - An address where the function will store the address of a finding.
 *     - An address where the function will store the value of a finding. You
 *     need to allocate enough space depending on the size of the values you're
 *     looking for.
 *
 * This function will return 1 each time it finds a matching value; the address
 * and the value arguments can be read. Once it ends the search it will return
 * 0. On failure it returns -1.
 */
int proctal_search(
	pid_t pid,
	proctal_search_state state,
	proctal_search_options options,
	void **addr,
	void *value);

proctal_search_state proctal_search_state_create();

void proctal_search_state_delete(proctal_search_state state);

proctal_search_options proctal_search_options_create();

size_t proctal_search_options_size(proctal_search_options options);

void proctal_search_options_set_size(proctal_search_options options, size_t size);

size_t proctal_search_options_align(proctal_search_options options);

void proctal_search_options_set_align(proctal_search_options options, size_t align);

void proctal_search_options_delete(proctal_search_options options);

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
