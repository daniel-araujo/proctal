#include "otrap/otrap.h"

void otrap_init(struct otrap *o);

void otrap_deinit(struct otrap *o);

int swbuf_error(struct otrap *o);

FILE *otrap_file(struct otrap *o);

size_t otrap_read(struct otrap *o, char *destination, size_t size);

size_t otrap_skip(struct otrap *o, size_t size);

FILE *otrap_create_file(void)
{
	return tmpfile();
}

void otrap_destroy_file(FILE *file)
{
	fclose(file);
}
