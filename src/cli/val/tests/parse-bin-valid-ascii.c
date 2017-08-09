#include <stdlib.h>
#include <stdio.h>

#include "cli/val/text.h"

int main(void)
{
	char characters[128];

	for (size_t i = 0; i < 128; ++i) {
		characters[i] = i;
	}

	struct cli_val_text_attr a;
	cli_val_text_attr_init(&a);
	cli_val_text_attr_encoding_set(&a, CLI_VAL_TEXT_ENCODING_ASCII);
	struct cli_val_text *v = cli_val_text_create(&a);
	cli_val_text_attr_deinit(&a);

	for (size_t i = 0; i < 128; ++i) {
		if (cli_val_text_parse_bin(v, &characters[i], 1) != 1) {
			fprintf(stderr, "cli_val_text_parse_bin failed on character #%lu\n", i + 1);
			cli_val_text_destroy(v);
			return 1;
		}
	}

	cli_val_text_destroy(v);

	return 0;
}
