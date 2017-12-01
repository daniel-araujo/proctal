#include "cli/val/text.h"

size_t cli_val_text_ascii_sizeof(struct cli_val_text *v);
int cli_val_text_ascii_cmp(struct cli_val_text *v, struct cli_val_text *other_v);
int cli_val_text_ascii_print(struct cli_val_text *v, FILE *f);
int cli_val_text_ascii_scan(struct cli_val_text *v, FILE *f);
int cli_val_text_ascii_parse_text(struct cli_val_text *v, const char *s);
int cli_val_text_ascii_parse_binary(struct cli_val_text *v, const void *b, size_t length);

struct cli_val_text_encoding_implementation {
	int (*size)(struct cli_val_text *);
	int (*cmp)(struct cli_val_text *, struct cli_val_text *);
	int (*print)(struct cli_val_text *, FILE *);
	int (*scan)(struct cli_val_text *, FILE *);
	int (*parse_text)(struct cli_val_text *, const char *);
	int (*parse_binary)(struct cli_val_text *, const void *, size_t);
};

static struct cli_val_text_encoding_implementation encoding_implementations[] = {
	[CLI_VAL_TEXT_ENCODING_ASCII] = {
		.size = (void *) cli_val_text_ascii_sizeof,
		.cmp = (void *) cli_val_text_ascii_cmp,
		.print = (void *) cli_val_text_ascii_print,
		.scan = (void *) cli_val_text_ascii_scan,
		.parse_text = (void *) cli_val_text_ascii_parse_text,
		.parse_binary = (void *) cli_val_text_ascii_parse_binary,
	},
};

static struct cli_val_text_encoding_implementation *get_encoding_implementation(enum cli_val_text_encoding encoding)
{
	assert(encoding < ARRAY_SIZE(encoding_implementations));

	return &encoding_implementations[encoding];
}

extern inline void cli_val_text_attr_init(struct cli_val_text_attr *a);

extern inline void cli_val_text_attr_encoding_set(struct cli_val_text_attr *a, enum cli_val_text_encoding encoding);

extern inline void cli_val_text_attr_deinit(struct cli_val_text_attr *a);

extern inline struct cli_val_text *cli_val_text_create(struct cli_val_text_attr *a);

extern inline void cli_val_text_destroy(struct cli_val_text *v);

extern inline void *cli_val_text_data(struct cli_val_text *v);

extern inline size_t cli_val_text_sizeof(struct cli_val_text *v);

extern inline int cli_val_text_parse_binary(struct cli_val_text *v, const void *b, size_t length);

extern inline int cli_val_text_print(struct cli_val_text *v, FILE *f);

extern inline int cli_val_text_scan(struct cli_val_text *v, FILE *f);

extern inline int cli_val_text_parse_text(struct cli_val_text *v, const char *s);

extern inline int cli_val_text_cmp(struct cli_val_text *v, struct cli_val_text *other_v);

extern inline struct cli_val_text *cli_val_text_create_clone(struct cli_val_text *other_v);

/*
 * Size of text character.
 */
size_t cli_val_text_sizeof(struct cli_val_text *v)
{
	return get_encoding_implementation(v->attr.encoding)->size(v);
}

int cli_val_text_cmp(struct cli_val_text *v, struct cli_val_text *other_v)
{
	if (v->attr.encoding != other_v->attr.encoding) {
		// We're going to consider text characters of different
		// encodings to be different.
		return 1;
	}

	return get_encoding_implementation(v->attr.encoding)->cmp(v, other_v);
}

int cli_val_text_print(struct cli_val_text *v, FILE *f)
{
	return get_encoding_implementation(v->attr.encoding)->print(v, f);
}

int cli_val_text_scan(struct cli_val_text *v, FILE *f)
{
	return get_encoding_implementation(v->attr.encoding)->scan(v, f);
}

int cli_val_text_parse_text(struct cli_val_text *v, const char *s)
{
	return get_encoding_implementation(v->attr.encoding)->parse_text(v, s);
}

int cli_val_text_parse_binary(struct cli_val_text *v, const void *b, size_t length)
{
	return get_encoding_implementation(v->attr.encoding)->parse_binary(v, b, length);
}
