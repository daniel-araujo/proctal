#ifndef API_PROCTAL_H
#define API_PROCTAL_H

/*
 * This is the header file that contains the declarations of the symbols that
 * are exposed to users.
 */
#include "api/include/proctal.h"

/*
 * Global state of the library that can be changed by the library user.
 *
 * Better kept small.
 */
extern struct proctal_global {
	// Memory allocator with the same signature as the malloc function from
	// the C standard library.
	void *(*malloc)(size_t);

	// Memory deallocator with the same signature as the free function from
	// the C standard library.
	void (*free)(void *);
} proctal_global;

/*
 * Base structure of a handle.
 *
 * Platform agnostic functions work with this structure.
 */
struct proctal {
	// Keeps track of the last error that was set.
	int error;

	/*
	 * Address iterator specific options.
	 */
	struct {
		// Tells which regions are iterated.
		long region_mask;

		// Address alignment.
		size_t align;

		// Size of the value of the address. We only want to return
		// addresses can be dereferenced up to this size.
		size_t size;

		// Whether to iterate over readable addresses.
		int read;

		// Whether to iterate over writable addresses.
		int write;

		// Whether to iterate over executable addresses.
		int execute;
	} address;

	/*
	 * Region iterator specific options.
	 */
	struct {
		// Tells which regions are iterated.
		long mask;

		// Whether to iterate over regions marked as readable.
		int read;

		// Whether to iterate over regions marked as writable.
		int write;

		// Whether to iterate over regions marked as executable.
		int execute;
	} region;

	/*
	 * Watch specific options.
	 */
	struct {
		// Address to watch.
		void *addr;

		// Whether to watch for reads.
		int read;

		// Whether to watch for writes.
		int write;

		// Whether to watch for instruction execution.
		int execute;
	} watch;

	/*
	 * Specific options for memory allocation.
	 */
	struct {
		// Read permission.
		int read;

		// Write permission.
		int write;

		// Execute permission.
		int execute;
	} allocate;
};

/*
 * Initializes fields in the base structure.
 */
void proctal_init(struct proctal *p);

/*
 * Deinitializes fields in the base structure.
 */
void proctal_deinit(struct proctal *p);

/*
 * Sets the error code of a handle.
 *
 * This is used to tell the library user what made a function fail.
 *
 * The error parameter must be a value available as a macro with the name
 * PROCTAL_ERROR as a prefix, otherwise library users won't have a way to check
 * what specific error proctal_error is returning.
 */
void proctal_error_set(struct proctal *p, int error);

/*
 * Allocates memory.
 *
 * Meant for internal data structures of a handle.
 */
void *proctal_malloc(struct proctal *p, size_t size);

/*
 * Deallocates memory allocated with proctal_malloc.
 *
 * Meant for internal data structures of a handle.
 */
void proctal_free(struct proctal *p, void *addr);

/*
 * Allocates memory.
 */
inline void *proctal_global_malloc(size_t size)
{
	return proctal_global.malloc(size);
}

/*
 * Deallocates memory allocated with proctal_global_malloc.
 */
inline void proctal_global_free(void *addr)
{
	proctal_global.free(addr);
}

#endif /* API_PROCTAL_H */
