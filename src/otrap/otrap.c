#include "otrap/otrap.h"

extern inline void otrap_init(struct otrap *o);

extern inline void otrap_deinit(struct otrap *o);

extern inline int swbuf_error(struct otrap *o);

extern inline FILE *otrap_file(struct otrap *o);

extern inline size_t otrap_read(
	struct otrap *o,
	char *destination,
	size_t size);

extern inline size_t otrap_skip(struct otrap *o, size_t size);

FILE *otrap_create_file(void)
{
	return tmpfile();
}

void otrap_destroy_file(FILE *file)
{
	fclose(file);
}
