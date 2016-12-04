#include <string.h>

#include "val-list.h"

struct cli_val_list {
	size_t size;

	// Whether this list owns the values. This gives it the right to
	// destroy them.
	int owner;

	cli_val data[0];
};

static void destroy_data(cli_val_list list)
{
	cli_val nil = cli_val_nil();

	for (size_t i = 0; i < list->size; ++i) {
		cli_val val = cli_val_list_get(list, i);

		if (val == nil) {
			continue;
		}

		cli_val_destroy(val);
	}
}

cli_val_list cli_val_list_create(size_t size)
{
	struct cli_val_list *list = (struct cli_val_list *) malloc((sizeof *list) + (sizeof (cli_val)) * size);
	list->size = size;
	list->owner = 1;

	for (size_t i = 0; i < size; ++i) {
		cli_val nil = cli_val_nil();

		memmove(list->data + i, &nil, sizeof (cli_val));
	}

	return list;
}

void cli_val_list_destroy(cli_val_list list)
{
	if (list->owner) {
		destroy_data(list);
	}

	free(list);
}

size_t cli_val_list_size(cli_val_list list)
{
	return list->size;
}

void cli_val_list_set(cli_val_list list, size_t pos, cli_val val)
{
	if (list->owner) {
		if (list->data[pos] != cli_val_nil()) {
			cli_val_destroy(list->data[pos]);
		}
	}

	list->data[pos] = val;
}

cli_val cli_val_list_get(cli_val_list list, size_t pos)
{
	return list->data[pos];
}

void cli_val_list_del(cli_val_list list, size_t pos)
{
	cli_val nil = cli_val_nil();

	if (list->owner && list->data[pos] != nil) {
		cli_val_destroy(list->data[pos]);
	}

	list->data[pos] = nil;
}
