#include <stdlib.h>
#include <stdio.h>

#include "cli/val/text.h"

int main(void)
{
	char strings[127 * 2] = { '\0' };

	for (size_t i = 0; i < 127; ++i) {
		strings[i * 2] = i + 1;
	}

	struct cli_val_text_attr a;
	cli_val_text_attr_init(&a);
	cli_val_text_attr_charset_set(&a, CLI_VAL_TEXT_CHARSET_ASCII);
	struct cli_val_text *v = cli_val_text_create(&a);
	cli_val_text_attr_deinit(&a);

	for (size_t i = 0; i < 127; ++i) {
		if (cli_val_text_parse(v, &strings[i * 2]) != 1) {
			fprintf(stderr, "cli_val_text_parse failed on string #%lu\n", i + 1);
			cli_val_text_destroy(v);
			return 1;
		}
	}

	cli_val_text_destroy(v);

	return 0;
}
