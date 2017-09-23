#include <assert.h>

#include "cli/val/text.h"

size_t cli_val_text_ascii_sizeof(struct cli_val_text *v)
{
	return 1;
}

int cli_val_text_ascii_cmp(struct cli_val_text *v, struct cli_val_text *other_v)
{
	return COMPARE_INT(DEREF(char, v->data), DEREF(char, other_v->data));
}

int cli_val_text_ascii_print(struct cli_val_text *v, FILE *f)
{
	return fprintf(f, "%c", DEREF(char, v->data));
}

int cli_val_text_ascii_scan(struct cli_val_text *v, FILE *f)
{
	return fscanf(f, "%c", v->data) == 1 ? 1 : 0;
}

int cli_val_text_ascii_parse_text(struct cli_val_text *v, const char *s)
{
	if (*s == '\0') {
		// End of the string.
		return 0;
	}

	if ((unsigned char) *s > 127) {
		// Not a valid ASCII character.
		return 0;
	}

	DEREF(char, v->data) = *s;

	return 1;
}

int cli_val_text_ascii_parse_binary(struct cli_val_text *v, const char *s, size_t length)
{
	if (length == 0) {
		return 0;
	}

	if ((unsigned char) *s > 127) {
		// Not a valid ASCII character.
		return 0;
	}

	DEREF(char, v->data) = *s;

	return 1;
}
