#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "cli/val.h"

/*
 * This is the data structure that implementations must fill to be wrapped.
 */
struct cli_val_impl {
	enum cli_val_type type;

	void (*address_set)(void *, void *);
	void *(*address)(void *);
	size_t (*align)(void *);
	size_t (*size)(void *);
	void *(*raw)(void *);
	int (*add)(void *, void *);
	int (*sub)(void *, void *);
	int (*cmp)(void *, void *);
	int (*print)(void *, FILE *);
	int (*scan)(void *, FILE *);
	int (*parse)(void *, const char *);
	int (*parse_bin)(void *, const char *, size_t length);

	void *(*create_clone)(void *);
	void (*destroy)(void *);
};

/*
 * The data structure that wraps a value together with its implementation.
 */
struct cli_val {
	struct cli_val_impl *impl;
	void *val;
};

/*
 * A non-existing value.
 */
static struct cli_val *nil = NULL;

/*
 * Always reports size to be one.
 */
static size_t size_one(void *val)
{
	return 1;
}

/*
 * All default implementations must be defined in this array.
 */
static struct cli_val_impl impls[] = {
	[CLI_VAL_TYPE_BYTE] = {
		.type = CLI_VAL_TYPE_BYTE,

		.size = (void *) size_one,
		.raw = (void *) cli_val_byte_raw,
		.add = (void *) cli_val_byte_add,
		.sub = (void *) cli_val_byte_sub,
		.cmp = (void *) cli_val_byte_cmp,
		.print = (void *) cli_val_byte_print,
		.scan = (void *) cli_val_byte_scan,
		.parse = (void *) cli_val_byte_parse,
		.parse_bin = (void *) cli_val_byte_parse_bin,

		.create_clone = (void *) cli_val_byte_create_clone,
		.destroy = (void *) cli_val_byte_destroy,
	},
	[CLI_VAL_TYPE_INTEGER] = {
		.type = CLI_VAL_TYPE_INTEGER,

		.align = (void *) cli_val_integer_alignof,
		.size = (void *) cli_val_integer_sizeof,
		.raw = (void *) cli_val_integer_raw,
		.add = (void *) cli_val_integer_add,
		.sub = (void *) cli_val_integer_sub,
		.cmp = (void *) cli_val_integer_cmp,
		.print = (void *) cli_val_integer_print,
		.scan = (void *) cli_val_integer_scan,
		.parse = (void *) cli_val_integer_parse,
		.parse_bin = (void *) cli_val_integer_parse_bin,

		.create_clone = (void *) cli_val_integer_create_clone,
		.destroy = (void *) cli_val_integer_destroy,
	},
	[CLI_VAL_TYPE_IEEE754] = {
		.type = CLI_VAL_TYPE_IEEE754,

		.align = (void *) cli_val_ieee754_alignof,
		.size = (void *) cli_val_ieee754_sizeof,
		.raw = (void *) cli_val_ieee754_raw,
		.add = (void *) cli_val_ieee754_add,
		.sub = (void *) cli_val_ieee754_sub,
		.cmp = (void *) cli_val_ieee754_cmp,
		.print = (void *) cli_val_ieee754_print,
		.scan = (void *) cli_val_ieee754_scan,
		.parse = (void *) cli_val_ieee754_parse,
		.parse_bin = (void *) cli_val_ieee754_parse_bin,

		.create_clone = (void *) cli_val_ieee754_create_clone,
		.destroy = (void *) cli_val_ieee754_destroy,
	},
	[CLI_VAL_TYPE_TEXT] = {
		.type = CLI_VAL_TYPE_TEXT,

		.size = (void *) cli_val_text_sizeof,
		.raw = (void *) cli_val_text_raw,
		.cmp = (void *) cli_val_text_cmp,
		.print = (void *) cli_val_text_print,
		.scan = (void *) cli_val_text_scan,
		.parse = (void *) cli_val_text_parse,
		.parse_bin = (void *) cli_val_text_parse_bin,

		.create_clone = (void *) cli_val_text_create_clone,
		.destroy = (void *) cli_val_text_destroy,
	},
	[CLI_VAL_TYPE_ADDRESS] = {
		.type = CLI_VAL_TYPE_ADDRESS,

		.align = (void *) cli_val_address_sizeof,
		.size = (void *) cli_val_address_sizeof,
		.raw = (void *) cli_val_address_raw,
		.cmp = (void *) cli_val_address_cmp,
		.print = (void *) cli_val_address_print,
		.scan = (void *) cli_val_address_scan,
		.parse = (void *) cli_val_address_parse,
		.parse_bin = (void *) cli_val_address_parse_bin,

		.create_clone = (void *) cli_val_address_create_clone,
		.destroy = (void *) cli_val_address_destroy,
	},
	[CLI_VAL_TYPE_INSTRUCTION] = {
		.type = CLI_VAL_TYPE_INSTRUCTION,

		.address_set = (void *) cli_val_instruction_address_set,
		.address = (void *) cli_val_instruction_address,
		.align = (void *) cli_val_instruction_sizeof,
		.size = (void *) cli_val_instruction_sizeof,
		.raw = (void *) cli_val_instruction_raw,
		.print = (void *) cli_val_instruction_print,
		.parse = (void *) cli_val_instruction_parse,
		.parse_bin = (void *) cli_val_instruction_parse_bin,

		.create_clone = (void *) cli_val_instruction_create_clone,
		.destroy = (void *) cli_val_instruction_destroy,
	},
};

/*
 * Retrieves a default implementation by its type.
 */
static struct cli_val_impl *get_impl_by_type(enum cli_val_type type)
{
	return &impls[type];
}

cli_val cli_val_wrap(enum cli_val_type type, void *val)
{
	struct cli_val_impl *impl = get_impl_by_type(type);

	if (impl == NULL) {
		return NULL;
	}

	struct cli_val *v = malloc(sizeof(*v));

	if (v == NULL) {
		return NULL;
	}

	v->impl = impl;
	v->val = val;

	return v;
}

void *cli_val_unwrap(cli_val v)
{
	void *val = v->val;

	free(v);

	return val;
}

cli_val cli_val_create_clone(cli_val other_v)
{
	void *val = other_v->impl->create_clone(other_v->val);

	return cli_val_wrap(other_v->impl->type, val);
}

void cli_val_destroy(cli_val v)
{
	v->impl->destroy(v->val);
	free(v);
}

void cli_val_address_set(cli_val v, void *addr)
{
	if (v->impl->address_set == NULL) {
		return;
	}

	return v->impl->address_set(v->val, addr);
}

void *cli_val_address(cli_val v)
{
	if (v->impl->address == NULL) {
		return NULL;
	}

	return v->impl->address(v->val);
}

enum cli_val_type cli_val_type(cli_val v)
{
	return v->impl->type;
}

size_t cli_val_alignof(cli_val v)
{
	if (v->impl->align == NULL) {
		return 1;
	}

	return v->impl->align(v->val);
}

size_t cli_val_sizeof(cli_val v)
{
	return v->impl->size(v->val);
}

void *cli_val_raw(cli_val v)
{
	return v->impl->raw(v->val);
}

int cli_val_add(cli_val v, cli_val other_v)
{
	if (v->impl->type != other_v->impl->type) {
		return 0;
	}

	if (v->impl->add == NULL) {
		return 0;
	}

	return v->impl->add(v->val, other_v->val);
}

int cli_val_sub(cli_val v, cli_val other_v)
{
	if (v->impl->type != other_v->impl->type) {
		return 0;
	}

	if (v->impl->sub == NULL) {
		return 0;
	}

	return v->impl->sub(v->val, other_v->val);
}

int cli_val_cmp(cli_val v, cli_val other_v)
{
	if (v->impl->type != other_v->impl->type) {
		return 0;
	}

	if (v->impl->cmp == NULL) {
		return 0;
	}

	return v->impl->cmp(v->val, other_v->val);
}

int cli_val_print(cli_val v, FILE *f)
{
	if (v->impl->print == NULL) {
		return 0;
	}

	return v->impl->print(v->val, f);
}

int cli_val_scan(cli_val v, FILE *f)
{
	if (v->impl->scan == NULL) {
		return 0;
	}

	return v->impl->scan(v->val, f);
}

int cli_val_parse(cli_val v, const char *s)
{
	if (v->impl->parse == NULL) {
		return 0;
	}

	return v->impl->parse(v->val, s);
}

int cli_val_parse_bin(cli_val v, const char *s, size_t length)
{
	if (v->impl->parse_bin == NULL) {
		return 0;
	}

	return v->impl->parse_bin(v->val, s, length);
}

cli_val cli_val_nil(void)
{
	return nil;
}
