#include <assert.h>

#include "cli/val/integer.h"
#include "magic/magic.h"

void cli_val_integer_endianness_convert(struct cli_val_integer *v);
void cli_val_integer_endianness_revert(struct cli_val_integer *v);

int cli_val_integer_unsigned_add(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v);
int cli_val_integer_unsigned_sub(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v);
int cli_val_integer_unsigned_cmp(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v);
int cli_val_integer_unsigned_print(struct cli_val_integer *v, FILE *f);
int cli_val_integer_unsigned_scan(struct cli_val_integer *v, FILE *f);
int cli_val_integer_unsigned_parse(struct cli_val_integer *v, const char *s);

int cli_val_integer_signed_add(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v);
int cli_val_integer_signed_sub(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v);
int cli_val_integer_signed_cmp(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v);
int cli_val_integer_signed_print(struct cli_val_integer *v, FILE *f);
int cli_val_integer_signed_scan(struct cli_val_integer *v, FILE *f);
int cli_val_integer_signed_parse(struct cli_val_integer *v, const char *s);

struct cli_val_integer_sign_impl {
	int (*add)(struct cli_val_integer *, struct cli_val_integer *);
	int (*sub)(struct cli_val_integer *, struct cli_val_integer *);
	int (*cmp)(struct cli_val_integer *, struct cli_val_integer *);
	int (*print)(struct cli_val_integer *, FILE *);
	int (*scan)(struct cli_val_integer *, FILE *);
	int (*parse)(struct cli_val_integer *, const char *);
};

static struct cli_val_integer_sign_impl impls[] = {
	[CLI_VAL_INTEGER_SIGN_UNSIGNED] = {
		.add = (void *) cli_val_integer_unsigned_add,
		.sub = (void *) cli_val_integer_unsigned_sub,
		.cmp = (void *) cli_val_integer_unsigned_cmp,
		.print = (void *) cli_val_integer_unsigned_print,
		.scan = (void *) cli_val_integer_unsigned_scan,
		.parse = (void *) cli_val_integer_unsigned_parse,
	},
	[CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT] = {
		// We are assuming that the C implementation of signed integers
		// uses two's complement.
		.add = (void *) cli_val_integer_signed_add,
		.sub = (void *) cli_val_integer_signed_sub,
		.cmp = (void *) cli_val_integer_signed_cmp,
		.print = (void *) cli_val_integer_signed_print,
		.scan = (void *) cli_val_integer_signed_scan,
		.parse = (void *) cli_val_integer_signed_parse,
	},
};

static struct cli_val_integer_sign_impl *get_sign_impl_by_sign(enum cli_val_integer_sign sign)
{
	assert(sign < ARRAY_SIZE(impls));

	return &impls[sign];
}

void cli_val_integer_attr_init(struct cli_val_integer_attr *a);

void cli_val_integer_attr_endianness_set(
	struct cli_val_integer_attr *a,
	enum cli_val_integer_endianness endianness);

void cli_val_integer_attr_size_set(
	struct cli_val_integer_attr *a,
	enum cli_val_integer_size size);

void cli_val_integer_attr_sign_set(
	struct cli_val_integer_attr *a,
	enum cli_val_integer_sign sign);

size_t cli_val_integer_attr_alignof(struct cli_val_integer_attr *a);

void cli_val_integer_attr_deinit(struct cli_val_integer_attr *a);

struct cli_val_integer *cli_val_integer_create(struct cli_val_integer_attr *a);

void cli_val_integer_destroy(struct cli_val_integer *v);

void *cli_val_integer_data(struct cli_val_integer *v);

size_t cli_val_integer_alignof(struct cli_val_integer *v);

size_t cli_val_integer_sizeof(struct cli_val_integer *v);

int cli_val_integer_parse_bin(struct cli_val_integer *v, const char *s, size_t length);

struct cli_val_integer *cli_val_integer_create_clone(struct cli_val_integer *other_v);

int cli_val_integer_add(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v)
{
	cli_val_integer_endianness_convert(v);
	int ret = get_sign_impl_by_sign(v->attr.sign)->add(v, other_v);
	cli_val_integer_endianness_revert(v);
	return ret;
}

int cli_val_integer_sub(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v)
{
	cli_val_integer_endianness_convert(v);
	int ret = get_sign_impl_by_sign(v->attr.sign)->sub(v, other_v);
	cli_val_integer_endianness_revert(v);
	return ret;
}

int cli_val_integer_cmp(
	struct cli_val_integer *v,
	struct cli_val_integer *other_v)
{
	return get_sign_impl_by_sign(v->attr.sign)->cmp(v, other_v);
}

int cli_val_integer_print(struct cli_val_integer *v, FILE *f)
{
	cli_val_integer_endianness_convert(v);
	int ret = get_sign_impl_by_sign(v->attr.sign)->print(v, f);
	cli_val_integer_endianness_revert(v);
	return ret;
}

int cli_val_integer_scan(struct cli_val_integer *v, FILE *f)
{
	cli_val_integer_endianness_convert(v);
	int ret = get_sign_impl_by_sign(v->attr.sign)->scan(v, f);
	cli_val_integer_endianness_revert(v);
	return ret;
}

int cli_val_integer_parse(struct cli_val_integer *v, const char *s)
{
	cli_val_integer_endianness_convert(v);
	int ret = get_sign_impl_by_sign(v->attr.sign)->parse(v, s);
	cli_val_integer_endianness_revert(v);
	return ret;
}
