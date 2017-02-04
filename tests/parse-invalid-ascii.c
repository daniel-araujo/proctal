#include <stdlib.h>
#include <stdio.h>

#include <cli/val/text.h>

int main(void)
{
	char strings[129 * 2] = { '\0' };

	for (size_t i = 0; i < 128; ++i) {
		strings[(i + 1) * 2] = i + 128;
	}

	struct cli_val_text_attr a;
	cli_val_text_attr_init(&a);
	cli_val_text_attr_set_charset(&a, CLI_VAL_TEXT_CHARSET_ASCII);
	struct cli_val_text *v = cli_val_text_create(&a);
	cli_val_text_attr_deinit(&a);

	for (size_t i = 0; i < 129; ++i) {
		if (cli_val_text_parse(v, &strings[i * 2]) != 0) {
			fprintf(stderr, "cli_val_text_parse accepted string #%lu\n", i + 1);
			cli_val_text_destroy(v);
			return 1;
		}
	}

	cli_val_text_destroy(v);

	return 0;
}
