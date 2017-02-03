#include <stdlib.h>
#include <stdio.h>

#include <cli/val/text.h>

inline static void init_characters(char *characters)
{
	for (size_t i = 0; i < 128; ++i) {
		characters[i] = i;
	}
}

int main(void)
{
	char characters[128];

	init_characters(characters);

	struct cli_val_text_attr a;
	cli_val_text_attr_init(&a);
	cli_val_text_attr_set_charset(&a, CLI_VAL_TEXT_CHARSET_ASCII);
	struct cli_val_text *v = cli_val_text_create(&a);
	cli_val_text_attr_deinit(&a);

	for (size_t i = 0; i < 128; ++i) {
		if (cli_val_text_parse_bin(v, &characters[i], 1) != 1) {
			fprintf(stderr, "cli_val_text_parse_bin failed on character #%lu\n", i);
			return 1;
		}

		if (cli_val_text_parse(v, &characters[i]) != 1) {
			fprintf(stderr, "cli_val_text_parse failed on character #%lu\n", i);
			return 1;
		}
	}

	return 0;
}
