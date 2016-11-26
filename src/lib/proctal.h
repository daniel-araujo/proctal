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
 * Base structure of an instance of Proctal.
 */
struct proctal {
	// Memory allocator and deallocator with the same signatures (and
	// names) as the standard malloc and free functions which are also used
	// by default.
	void *(*malloc)(size_t);
	void (*free)(void *);

	// Keeps track of the last error that was set.
	int error;
};

/*
 * Base structure of an address iterator.
 */
struct proctal_addr_iter {
	// Start address of the next call.
	void *curr_addr;

	// Tells which regions are iterated.
	long region_mask;

	// Address alignment.
	size_t align;

	// Size of the value of the address. We only want to return addresses
	// that when dereferenced can return values of up to this size.
	size_t size;

	// Whether we have started iterating over addresses.
	int started;

	// Whether to iterate over readable addresses.
	int read;

	// Whether to iterate over writable addresses.
	int write;

	// Whether to iterate over executable addresses.
	int execute;
};

/*
 * Base structure of a watch.
 */
struct proctal_watch {
	// Address to watch.
	void *addr;

	// Tells us when it has started.
	int started;

	// Whether to watch for reads.
	int read;

	// Whether to watch for writes.
	int write;

	// Whether to watch for instruction execution.
	int execute;
};

/*
 * Initializes fields in the base structure.
 */
void proctal_init(struct proctal *p);

/*
 * Deinitializes fields in the base structure.
 */
void proctal_deinit(struct proctal *p);

void proctal_addr_iter_init(struct proctal *p, struct proctal_addr_iter *iter);

void proctal_addr_iter_deinit(struct proctal *p, struct proctal_addr_iter *iter);

void proctal_watch_init(struct proctal *p, struct proctal_watch *w);

void proctal_watch_deinit(struct proctal *p, struct proctal_watch *w);

/*
 * Sets the error of an instance of Proctal.
 *
 * The error parameter must be a value available as a macro with the name
 * PROCTAL_ERROR as a prefix, otherwise library users won't have a way to know
 * what the error is.
 */
void proctal_set_error(proctal p, int error);

/*
 * Allocates and deallocates memory.
 */
void *proctal_alloc(proctal p, size_t size);
void proctal_dealloc(proctal p, void *addr);

inline void *proctal_align_addr(void *addr, size_t align)
{
	ptrdiff_t offset = ((unsigned long) addr % align);

	if (offset != 0) {
		offset = align - offset;
	}

	return (void *) ((char *) addr + offset);
}

#endif /* PROCTAL_H */
