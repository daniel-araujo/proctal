#include "cli/cmd/measure.h"
#include "cli/vmagazine.h"
#include "cli/printer.h"
#include "api/include/proctal.h"

int cli_cmd_measure(struct cli_cmd_measure_arg *arg)
{
	int ret = 1;

	struct vmagazine vmagazine;
	if (vmagazine_init(&vmagazine) != VMAGAZINE_OK) {
		fprintf(stderr, "Initialization failure.\n");
		goto exit0;
	}
	vmagazine_template_value_set(&vmagazine, arg->value);
	vmagazine_template_address_set(&vmagazine, arg->address);

	if (vmagazine_size(&vmagazine) == 0) {
		for (size_t i = 0; i < arg->values_size; ++i) {
			const char *value = arg->values[i];

			switch (vmagazine_parse_text(&vmagazine, value, strlen(value))) {
			case VMAGAZINE_OK:
				break;

			case VMAGAZINE_PARSE_FAILURE:
			default:
				fprintf(stderr, "Failed to parse argument #%d.\n", (int) i + 1);
				goto exit1;
			}
		}

		if (vmagazine_size(&vmagazine) == 0) {
			fprintf(stderr, "No values found.\n");
			goto exit1;
		}
	}

	size_t total_size = 0;
	size_t array = arg->array;

	if (array == 0) {
		array = vmagazine_size(&vmagazine);
	}

	for (size_t i = 0, j = 0; i < array; ++i, ++j) {
		if (j == vmagazine_size(&vmagazine)) {
			j = 0;
		}

		cli_val *v = vmagazine_value(&vmagazine, j);

		total_size += cli_val_sizeof(*v);
	}

	cli_print_size(total_size);
	cli_print_nl();

	ret = 0;
exit1:
	vmagazine_deinit(&vmagazine);
exit0:
	return ret;
}
