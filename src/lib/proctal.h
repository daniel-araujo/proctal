#ifndef LIB_PROCTAL_H
#define LIB_PROCTAL_H

#include "lib/include/proctal.h"
#include "lib/impl/impl.h"

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
 * Base structure of an instance.
 *
 * Platform agnostic functions work with this structure.
 */
struct proctal {
	// Memory allocator with the same signature as the malloc function from
	// the C standard library.
	void *(*malloc)(size_t);

	// Memory deallocator with the same signature as the free function from
	// the C standard library.
	void (*free)(void *);

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
 * Sets the error code of an instance.
 *
 * This is used to tell the library user what made a function fail.
 *
 * The error parameter must be a value available as a macro with the name
 * PROCTAL_ERROR as a prefix, otherwise library users won't have a way to check
 * what specific error proctal_error is returning.
 */
void proctal_set_error(proctal p, int error);

/*
 * Allocates memory.
 *
 * Meant for internal data structures of an instance.
 */
void *proctal_malloc(proctal p, size_t size);

/*
 * Deallocates memory allocated with proctal_malloc.
 *
 * Meant for internal data structures of an instance.
 */
void proctal_free(proctal p, void *addr);

/*
 * Allocates memory.
 *
 * This version should only be used for internal data structures needed to
 * create an instance.
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

#endif /* LIB_PROCTAL_H */
