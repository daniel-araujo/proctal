#include <stdlib.h>
#include <stdio.h>

#include "cli/val/text.h"

int main(void)
{
	char characters[128];

	for (size_t i = 0; i < 128; ++i) {
		characters[i] = i + 128;
	}

	struct cli_val_text_attr a;
	cli_val_text_attr_init(&a);
	cli_val_text_attr_set_charset(&a, CLI_VAL_TEXT_CHARSET_ASCII);
	struct cli_val_text *v = cli_val_text_create(&a);
	cli_val_text_attr_deinit(&a);

	for (size_t i = 0; i < 128; ++i) {
		if (cli_val_text_parse_bin(v, &characters[i], 1) != 0) {
			fprintf(stderr, "cli_val_text_parse_bin accepted character #%lu\n", i + 1);
			cli_val_text_destroy(v);
			return 1;
		}
	}

	cli_val_text_destroy(v);

	return 0;
}
