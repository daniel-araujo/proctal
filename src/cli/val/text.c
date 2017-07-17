#include "cli/val/text.h"

size_t cli_val_text_ascii_sizeof(struct cli_val_text *v);
int cli_val_text_ascii_cmp(
	struct cli_val_text *v,
	struct cli_val_text *other_v);
int cli_val_text_ascii_print(struct cli_val_text *v, FILE *f);
int cli_val_text_ascii_scan(struct cli_val_text *v, FILE *f);
int cli_val_text_ascii_parse(struct cli_val_text *v, const char *s);
int cli_val_text_ascii_parse_bin(struct cli_val_text *v, const char *s, size_t length);

struct cli_val_text_charset_impl {
	int (*size)(struct cli_val_text *);
	int (*cmp)(struct cli_val_text *, struct cli_val_text *);
	int (*print)(struct cli_val_text *, FILE *);
	int (*scan)(struct cli_val_text *, FILE *);
	int (*parse)(struct cli_val_text *, const char *);
	int (*parse_bin)(struct cli_val_text *, const char *, size_t);
};

static struct cli_val_text_charset_impl impls[] = {
	[CLI_VAL_TEXT_CHARSET_ASCII] = {
		.size = (void *) cli_val_text_ascii_sizeof,
		.cmp = (void *) cli_val_text_ascii_cmp,
		.print = (void *) cli_val_text_ascii_print,
		.scan = (void *) cli_val_text_ascii_scan,
		.parse = (void *) cli_val_text_ascii_parse,
		.parse_bin = (void *) cli_val_text_ascii_parse_bin,
	},
};

static struct cli_val_text_charset_impl *get_charset_impl_by_charset(enum cli_val_text_charset charset)
{
	assert(charset < ARRAY_SIZE(impls));

	return &impls[charset];
}

void cli_val_text_attr_init(struct cli_val_text_attr *a);

void cli_val_text_attr_charset_set(
	struct cli_val_text_attr *a,
	enum cli_val_text_charset charset);

void cli_val_text_attr_deinit(struct cli_val_text_attr *a);

struct cli_val_text *cli_val_text_create(struct cli_val_text_attr *a);

void cli_val_text_destroy(struct cli_val_text *v);

void *cli_val_text_data(struct cli_val_text *v);

size_t cli_val_text_sizeof(struct cli_val_text *v);

int cli_val_text_parse_bin(struct cli_val_text *v, const char *s, size_t length);

int cli_val_text_print(struct cli_val_text *v, FILE *f);

int cli_val_text_scan(struct cli_val_text *v, FILE *f);

int cli_val_text_parse(struct cli_val_text *v, const char *s);

int cli_val_text_cmp(
	struct cli_val_text *v,
	struct cli_val_text *other_v);

struct cli_val_text *cli_val_text_create_clone(struct cli_val_text *other_v);

/*
 * Size of text character.
 */
size_t cli_val_text_sizeof(struct cli_val_text *v)
{
	return get_charset_impl_by_charset(v->attr.charset)->size(v);
}

int cli_val_text_cmp(
	struct cli_val_text *v,
	struct cli_val_text *other_v)
{
	if (v->attr.charset != other_v->attr.charset) {
		// We're going to consider text characters of different
		// encodings to be different.
		return 1;
	}

	return get_charset_impl_by_charset(v->attr.charset)->cmp(v, other_v);
}

int cli_val_text_print(struct cli_val_text *v, FILE *f)
{
	return get_charset_impl_by_charset(v->attr.charset)->print(v, f);
}

int cli_val_text_scan(struct cli_val_text *v, FILE *f)
{
	return get_charset_impl_by_charset(v->attr.charset)->scan(v, f);
}

int cli_val_text_parse(struct cli_val_text *v, const char *s)
{
	return get_charset_impl_by_charset(v->attr.charset)->parse(v, s);
}

int cli_val_text_parse_bin(struct cli_val_text *v, const char *s, size_t length)
{
	return get_charset_impl_by_charset(v->attr.charset)->parse_bin(v, s, length);
}
