#ifndef VAL_TEXT_H
#define VAL_TEXT_H

#include <stdlib.h>
#include <stdio.h>
#include <stdalign.h>
#include <assert.h>
#include <string.h>

/*
 * Supported character sets.
 */
enum cli_val_text_charset {
	CLI_VAL_TEXT_CHARSET_ASCII,
};

/*
 * Describes the behavior of the text character.
 */
struct cli_val_text_attr {
	enum cli_val_text_charset charset;
};

/*
 * Represents a text character.
 */
struct cli_val_text {
	struct cli_val_text_attr attr;
	char data[0];
};

/*
 * Sets the initial state of text attributes.
 */
inline void cli_val_text_attr_init(struct cli_val_text_attr *a)
{
	a->charset = CLI_VAL_TEXT_CHARSET_ASCII;
}

/*
 * Sets chararacter set.
 */
inline void cli_val_text_attr_set_charset(
	struct cli_val_text_attr *a,
	enum cli_val_text_charset charset)
{
	a->charset = charset;
}

/*
 * Disposes it off.
 */
inline void cli_val_text_attr_deinit(struct cli_val_text_attr *a)
{
}

/*
 * Creates a text character.
 *
 * By default it's some random character that previously sat in memory.
 *
 * Returns a NULL pointer on failure.
 */
inline struct cli_val_text *cli_val_text_create(struct cli_val_text_attr *a)
{
	size_t size;

	switch (a->charset) {
	case CLI_VAL_TEXT_CHARSET_ASCII:
		// An ASCII character can be represented in only 7 bits. A
		// single byte will be enough.
		size = 1;
		break;

	default:
		// Not expecting to ever reach here.
		assert(0);
	}

	struct cli_val_text *v = malloc(sizeof(*v) + size);

	if (v == NULL) {
		return NULL;
	}

	v->attr = *a;

	return v;
}

/*
 * Destroys a text character created by a call to cli_val_text_create.
 *
 * Must only be used once on the same structure and not be NULL.
 */
inline void cli_val_text_destroy(struct cli_val_text *v)
{
	free(v);
}

/*
 * Returns a pointer to the raw data that represents a text character.
 *
 * The pointer can be dereferenced but you really must know what you're
 * doing.
 */
inline void *cli_val_text_raw(struct cli_val_text *v)
{
	return v->data;
}

/*
 * Size of text character.
 */
inline size_t cli_val_text_sizeof(struct cli_val_text *v)
{
	switch (v->attr.charset) {
	case CLI_VAL_TEXT_CHARSET_ASCII:
		return 1;
	}

	// Not expecting to ever reach here.
	assert(0);
}

/*
 * Attempts to interpret a text value from a stream of bytes.
 *
 * Returns how many bytes were consumed on success, 0 on failure.
 */
inline int cli_val_text_parse_bin(struct cli_val_text *v, const char *s, size_t length)
{
	switch (v->attr.charset) {
	case CLI_VAL_TEXT_CHARSET_ASCII:
		if (length == 0) {
			return 0;
		}

		if ((unsigned char) *s > 127) {
			// Not a valid ASCII character.
			return 0;
		}

		*(char *) v->data = *s;

		return 1;
	}

	// Not expecting to ever reach here.
	assert(0);
}

/*
 * Attempts to write the text value as text to a file.
 *
 * Returns how many characters were written.
 */
inline int cli_val_text_print(struct cli_val_text *v, FILE *f)
{
	return fprintf(f, "%c", *(char *) v->data);
}

/*
 * Attempts to read the text value as text from a file.
 *
 * Returns 1 on success, 0 on failure.
 */
inline int cli_val_text_scan(struct cli_val_text *v, FILE *f)
{
	return fscanf(f, "%c", v->data) == 1 ? 1 : 0;
}

/*
 * Attempts to parse the text value as text from a C-style string.
 *
 * Returns 1 on success, 0 on failure.
 */
inline int cli_val_text_parse(struct cli_val_text *v, const char *s)
{
	return sscanf(s, "%c", v->data) == 1 ? 1 : 0;
}

/*
 * Compares two text characters.
 *
 * Returns 0 if they're equal.
 * Returns either 1 or -1 if they're different.
 */
inline int cli_val_text_cmp(
	struct cli_val_text *v1,
	struct cli_val_text *v2)
{
	if (v1->attr.charset != v2->attr.charset) {
		// We're going to consider text characters of different
		// encodings to be different.
		return 1;
	}

	switch (v1->attr.charset) {
	case CLI_VAL_TEXT_CHARSET_ASCII:
		return *(char *) v1->data == *(char *) v2->data ? 0 : -1;
	}

	// Not expecting to ever reach here.
	assert(0);
}

/*
 * Creates a new text value based off an existing one.
 *
 * Returns null on failure.
 */
inline struct cli_val_text *cli_val_text_create_clone(struct cli_val_text *other_v)
{
	struct cli_val_text *v = cli_val_text_create(&other_v->attr);

	if (v == NULL) {
		return NULL;
	}

	cli_val_text_parse_bin(v, other_v->data, cli_val_text_sizeof(v));

	return v;
}

#endif /* VAL_TEXT_H */
