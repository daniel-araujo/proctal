#ifndef PROCTAL_H
// Include guard macro will be defined by the following include statement. It
// just so happens the included header file also uses the same macro name.
#include <include/proctal.h>

#include <impl/impl.h>

/*
 * Global variables. Keep these to a minimum.
 */
extern void *(*proctal_global_malloc)(size_t);
extern void (*proctal_global_free)(void *);

/*
 * Base structure of an instance.
 */
struct proctal {
	// Memory allocator and deallocator with the same signatures (and
	// names) as the standard malloc and free functions which are also used
	// by default.
	void *(*malloc)(size_t);
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

		// Size of the value of the address. We only want to return addresses
		// that when dereferenced can return values of up to this size.
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
 * Sets error of an instance.
 *
 * The error parameter must be a value available as a macro with the name
 * PROCTAL_ERROR as a prefix, otherwise library users won't have a way to know
 * what the error is.
 */
void proctal_set_error(proctal p, int error);

/*
 * Allocates and deallocates memory for internal data structures.
 */
void *proctal_malloc(proctal p, size_t size);
void proctal_free(proctal p, void *addr);

inline void *proctal_align_addr(void *addr, size_t align)
{
	ptrdiff_t offset = ((unsigned long) addr % align);

	if (offset != 0) {
		offset = align - offset;
	}

	return (void *) ((char *) addr + offset);
}

#endif /* PROCTAL_H */
