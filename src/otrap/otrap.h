#ifndef OTRAP_OTRAP_H
#define OTRAP_OTRAP_H

#include <stdio.h>

struct otrap {
	// Read offset.
	size_t r_offset;

	// File used for trapping output.
	FILE *file;
};

/*
 * This is an implementation detail. Do not call this function.
 *
 * Creates a read and write capable FILE structure.
 */
FILE *otrap_create_file(void);

/*
 * This is an implementation detail. Do not call this function.
 *
 * Destroys a FILE structure created by otrap_create_file.
 */
void otrap_destroy_file(FILE *file);

/*
 * Initialize an otrap struct.
 */
inline void otrap_init(struct otrap *o)
{
	o->r_offset = 0;
	o->file = otrap_create_file();
}

/*
 * Deinitialize an otrap struct.
 */
inline void otrap_deinit(struct otrap *o)
{
	if (o->file) {
		otrap_destroy_file(o->file);
	}
}

/*
 * Returns 1 if an error ocurred, 0 if everything is ok.
 */
inline int swbuf_error(struct otrap *o)
{
	return o->file == NULL;
}

/*
 * Returns the FILE structure that will be used to capture output.
 */
inline FILE *otrap_file(struct otrap *o)
{
	return o->file;
}

/*
 * Read captured output.
 *
 * Returns the number of characters written to destination.
 */
inline size_t otrap_read(struct otrap *o, char *destination, size_t size)
{
	size_t original_offset = ftell(o->file);

	fseek(o->file, o->r_offset, SEEK_SET);

	size_t read = fread(destination, 1, size, o->file);

	o->r_offset += read;

	fseek(o->file, original_offset, SEEK_SET);

	return read;
}

/*
 * Skip captured output.
 *
 * Returns how many characters were skipped.
 */
inline size_t otrap_skip(struct otrap *o, size_t size)
{
	size_t original_offset = ftell(o->file);

	size_t remaining = original_offset - o->r_offset;

	if (size > remaining) {
		size = remaining;
	}

	o->r_offset += size;

	return size;
}

#endif /* OTRAP_OTRAP_H */
