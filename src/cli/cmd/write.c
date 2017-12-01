#include <unistd.h>

#include "cli/vmagazine.h"
#include "cli/cmd/write.h"
#include "cli/printer.h"
#include "api/include/proctal.h"

typedef int (*writer_t)(struct cli_cmd_write_arg *arg, proctal_t p, struct vmagazine *vmagazine);

static inline int fire_magazine(struct cli_cmd_write_arg *arg, proctal_t p, struct vmagazine *vmagazine)
{
	char *address = (char *) arg->address;
	size_t array = arg->array;

	if (array == 0) {
		array = vmagazine_size(vmagazine);
	}

	for (size_t i = 0, j = 0; i < array; ++i, ++j) {
		if (j == vmagazine_size(vmagazine)) {
			j = 0;
		}

		cli_val_t *v = vmagazine_value(vmagazine, j);

		size_t size = cli_val_sizeof(*v);
		void *input = cli_val_data(*v);

		proctal_write(p, address, input, size);

		if (proctal_error(p)) {
			cli_print_proctal_error(p);
			return 0;
		}

		address += size;
	}

	return 1;
}

/*
 * Writes text input.
 *
 * Returns 1 on success, 0 on failure.
 *
 * Additionally prints an error message on failure.
 */
static inline int write_text(struct cli_cmd_write_arg *arg, proctal_t p, struct vmagazine *vmagazine)
{
	if (arg->values_size == 0) {
		fputs("You must provide at least 1 value.\n", stderr);
		return 0;
	}

	if (vmagazine_size(vmagazine) == 0) {
		for (size_t i = 0; i < arg->values_size; ++i) {
			const char *value = arg->values[i];

			switch (vmagazine_parse_text(vmagazine, value, strlen(value))) {
			case VMAGAZINE_OK:
				break;

			case VMAGAZINE_PARSE_FAILURE:
			default:
				fprintf(stderr, "Failed to parse argument #%d.\n", (int) i + 1);
				return 0;
			}
		}

		if (vmagazine_size(vmagazine) == 0) {
			fprintf(stderr, "No values found.\n");
			return 0;
		}
	}

	return fire_magazine(arg, p, vmagazine);
}

/*
 * Writes binary input.
 *
 * Returns 1 on success, 0 on failure.
 *
 * Additionally prints an error message on failure.
 */
static inline int write_binary(struct cli_cmd_write_arg *arg, proctal_t p, struct vmagazine *vmagazine)
{
	if (vmagazine_size(vmagazine) == 0) {
		unsigned char buffer[16];
		size_t unread = 0;
		size_t offset = 0;

		while (!feof(stdin)) {
			unread += fread(buffer + unread, 1, ARRAY_SIZE(buffer) - unread, stdin);

			if (unread == 0) {
				break;
			}

			size_t read;

			switch (vmagazine_parse_binary(vmagazine, buffer, unread, &read)) {
			case VMAGAZINE_OK:
				break;

			case VMAGAZINE_PARSE_FAILURE:
			default:
				fprintf(stderr, "Failed to parse value at offset %d.\n", (int) offset);
				return 0;
			}

			unread -= read;
			memmove(buffer, buffer + read, unread);
			offset += read;
		}

		if (vmagazine_size(vmagazine) == 0) {
			fprintf(stderr, "No values found.\n");
			return 0;
		}
	}

	return fire_magazine(arg, p, vmagazine);
}

int cli_cmd_write(struct cli_cmd_write_arg *arg)
{
	int ret = 1;

	writer_t write = arg->binary ? write_binary : write_text;

	proctal_t p = proctal_open();

	if (proctal_error(p)) {
		cli_print_proctal_error(p);
		goto exit1;
	}

	proctal_pid_set(p, arg->pid);

	if (arg->freeze) {
		proctal_freeze(p);

		if (proctal_error(p)) {
			cli_print_proctal_error(p);
			goto exit1;
		}
	}

	struct vmagazine vmagazine;
	if (vmagazine_init(&vmagazine) != VMAGAZINE_OK) {
		fprintf(stderr, "Initialization failure.\n");
		goto exit2;
	}
	vmagazine_template_value_set(&vmagazine, arg->value);

	do {
		if (!write(arg, p, &vmagazine)) {
			goto exit3;
		}

		if (arg->repeat && arg->repeat_delay > 0) {
			usleep(arg->repeat_delay * 1000);
		}
	} while (arg->repeat);

	ret = 0;
exit3:
	vmagazine_deinit(&vmagazine);
exit2:
	if (arg->freeze) {
		proctal_unfreeze(p);
	}
exit1:
	proctal_close(p);
exit0:
	return ret;
}
