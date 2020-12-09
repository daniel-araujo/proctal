#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>

#include "cli/val/val.h"

/*
 * This is the data structure that types must fill to have their values
 * wrapped.
 */
struct cli_val_implementation {
	enum cli_val_type type;

	void (*address_set)(void *, void *);
	void *(*address)(void *);
	size_t (*align)(void *);
	size_t (*size)(void *);
	void *(*data)(void *);
	int (*add)(void *, void *);
	int (*sub)(void *, void *);
	int (*cmp)(void *, void *);
	int (*print)(void *, FILE *);
	int (*scan)(void *, FILE *);
	int (*parse_text)(void *, const char *);
	int (*parse_binary)(void *, const void *, size_t);

	void *(*create_clone)(void *);
	void (*destroy)(void *);
};

/*
 * The data structure that wraps a value together with its implementation.
 */
struct cli_val {
	struct cli_val_implementation *implementation;
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
static struct cli_val_implementation implementations[] = {
	[CLI_VAL_TYPE_BYTE] = {
		.type = CLI_VAL_TYPE_BYTE,

		.size = (void *) size_one,
		.data = (void *) cli_val_byte_data,
		.add = (void *) cli_val_byte_add,
		.sub = (void *) cli_val_byte_sub,
		.cmp = (void *) cli_val_byte_cmp,
		.print = (void *) cli_val_byte_print,
		.scan = (void *) cli_val_byte_scan,
		.parse_text = (void *) cli_val_byte_parse_text,
		.parse_binary = (void *) cli_val_byte_parse_binary,

		.create_clone = (void *) cli_val_byte_create_clone,
		.destroy = (void *) cli_val_byte_destroy,
	},
	[CLI_VAL_TYPE_INTEGER] = {
		.type = CLI_VAL_TYPE_INTEGER,

		.align = (void *) cli_val_integer_alignof,
		.size = (void *) cli_val_integer_sizeof,
		.data = (void *) cli_val_integer_data,
		.add = (void *) cli_val_integer_add,
		.sub = (void *) cli_val_integer_sub,
		.cmp = (void *) cli_val_integer_cmp,
		.print = (void *) cli_val_integer_print,
		.scan = (void *) cli_val_integer_scan,
		.parse_text = (void *) cli_val_integer_parse_text,
		.parse_binary = (void *) cli_val_integer_parse_binary,

		.create_clone = (void *) cli_val_integer_create_clone,
		.destroy = (void *) cli_val_integer_destroy,
	},
	[CLI_VAL_TYPE_IEEE754] = {
		.type = CLI_VAL_TYPE_IEEE754,

		.align = (void *) cli_val_ieee754_alignof,
		.size = (void *) cli_val_ieee754_sizeof,
		.data = (void *) cli_val_ieee754_data,
		.add = (void *) cli_val_ieee754_add,
		.sub = (void *) cli_val_ieee754_sub,
		.cmp = (void *) cli_val_ieee754_cmp,
		.print = (void *) cli_val_ieee754_print,
		.scan = (void *) cli_val_ieee754_scan,
		.parse_text = (void *) cli_val_ieee754_parse_text,
		.parse_binary = (void *) cli_val_ieee754_parse_binary,

		.create_clone = (void *) cli_val_ieee754_create_clone,
		.destroy = (void *) cli_val_ieee754_destroy,
	},
	[CLI_VAL_TYPE_TEXT] = {
		.type = CLI_VAL_TYPE_TEXT,

		.size = (void *) cli_val_text_sizeof,
		.data = (void *) cli_val_text_data,
		.cmp = (void *) cli_val_text_cmp,
		.print = (void *) cli_val_text_print,
		.scan = (void *) cli_val_text_scan,
		.parse_text = (void *) cli_val_text_parse_text,
		.parse_binary = (void *) cli_val_text_parse_binary,

		.create_clone = (void *) cli_val_text_create_clone,
		.destroy = (void *) cli_val_text_destroy,
	},
	[CLI_VAL_TYPE_ADDRESS] = {
		.type = CLI_VAL_TYPE_ADDRESS,

		.align = (void *) cli_val_address_alignof,
		.size = (void *) cli_val_address_sizeof,
		.data = (void *) cli_val_address_data,
		.cmp = (void *) cli_val_address_cmp,
		.print = (void *) cli_val_address_print,
		.scan = (void *) cli_val_address_scan,
		.parse_text = (void *) cli_val_address_parse_text,
		.parse_binary = (void *) cli_val_address_parse_binary,

		.create_clone = (void *) cli_val_address_create_clone,
		.destroy = (void *) cli_val_address_destroy,
	},
	[CLI_VAL_TYPE_X86] = {
		.type = CLI_VAL_TYPE_X86,

		.address_set = (void *) cli_val_x86_address_set,
		.address = (void *) cli_val_x86_address,
		.size = (void *) cli_val_x86_sizeof,
		.data = (void *) cli_val_x86_data,
		.print = (void *) cli_val_x86_print,
		.parse_text = (void *) cli_val_x86_parse_text,
		.parse_binary = (void *) cli_val_x86_parse_binary,

		.create_clone = (void *) cli_val_x86_create_clone,
		.destroy = (void *) cli_val_x86_destroy,
	},
	[CLI_VAL_TYPE_ARM] = {
		.type = CLI_VAL_TYPE_ARM,

		.address_set = (void *) cli_val_arm_address_set,
		.address = (void *) cli_val_arm_address,
		.size = (void *) cli_val_arm_sizeof,
		.data = (void *) cli_val_arm_data,
		.print = (void *) cli_val_arm_print,
		.parse_text = (void *) cli_val_arm_parse_text,
		.parse_binary = (void *) cli_val_arm_parse_binary,

		.create_clone = (void *) cli_val_arm_create_clone,
		.destroy = (void *) cli_val_arm_destroy,
	},
	[CLI_VAL_TYPE_SPARC] = {
		.type = CLI_VAL_TYPE_SPARC,

		.address_set = (void *) cli_val_sparc_address_set,
		.address = (void *) cli_val_sparc_address,
		.size = (void *) cli_val_sparc_sizeof,
		.data = (void *) cli_val_sparc_data,
		.print = (void *) cli_val_sparc_print,
		.parse_text = (void *) cli_val_sparc_parse_text,
		.parse_binary = (void *) cli_val_sparc_parse_binary,

		.create_clone = (void *) cli_val_sparc_create_clone,
		.destroy = (void *) cli_val_sparc_destroy,
	},
	[CLI_VAL_TYPE_POWERPC] = {
		.type = CLI_VAL_TYPE_POWERPC,

		.address_set = (void *) cli_val_powerpc_address_set,
		.address = (void *) cli_val_powerpc_address,
		.size = (void *) cli_val_powerpc_sizeof,
		.data = (void *) cli_val_powerpc_data,
		.print = (void *) cli_val_powerpc_print,
		.parse_text = (void *) cli_val_powerpc_parse_text,
		.parse_binary = (void *) cli_val_powerpc_parse_binary,

		.create_clone = (void *) cli_val_powerpc_create_clone,
		.destroy = (void *) cli_val_powerpc_destroy,
	},
	[CLI_VAL_TYPE_MIPS] = {
		.type = CLI_VAL_TYPE_MIPS,

		.address_set = (void *) cli_val_mips_address_set,
		.address = (void *) cli_val_mips_address,
		.size = (void *) cli_val_mips_sizeof,
		.data = (void *) cli_val_mips_data,
		.print = (void *) cli_val_mips_print,
		.parse_text = (void *) cli_val_mips_parse_text,
		.parse_binary = (void *) cli_val_mips_parse_binary,

		.create_clone = (void *) cli_val_mips_create_clone,
		.destroy = (void *) cli_val_mips_destroy,
	},
};

/*
 * Retrieves a default implementation by its type.
 */
static struct cli_val_implementation *get_implementation(enum cli_val_type type)
{
	return &implementations[type];
}

cli_val_t cli_val_wrap(enum cli_val_type type, void *val)
{
	struct cli_val_implementation *implementation = get_implementation(type);

	if (implementation == NULL) {
		return NULL;
	}

	struct cli_val *v = malloc(sizeof(*v));

	if (v == NULL) {
		return NULL;
	}

	v->implementation = implementation;
	v->val = val;

	return v;
}

void *cli_val_unwrap(cli_val_t v)
{
	void *val = v->val;

	free(v);

	return val;
}

cli_val_t cli_val_create_clone(cli_val_t other_v)
{
	void *val = other_v->implementation->create_clone(other_v->val);

	return cli_val_wrap(other_v->implementation->type, val);
}

void cli_val_destroy(cli_val_t v)
{
	v->implementation->destroy(v->val);
	free(v);
}

void cli_val_address_set(cli_val_t v, void *addr)
{
	if (v->implementation->address_set == NULL) {
		return;
	}

	return v->implementation->address_set(v->val, addr);
}

void *cli_val_address(cli_val_t v)
{
	if (v->implementation->address == NULL) {
		return NULL;
	}

	return v->implementation->address(v->val);
}

enum cli_val_type cli_val_type(cli_val_t v)
{
	return v->implementation->type;
}

size_t cli_val_alignof(cli_val_t v)
{
	if (v->implementation->align == NULL) {
		return 1;
	}

	return v->implementation->align(v->val);
}

size_t cli_val_sizeof(cli_val_t v)
{
	return v->implementation->size(v->val);
}

void *cli_val_data(cli_val_t v)
{
	return v->implementation->data(v->val);
}

int cli_val_add(cli_val_t v, cli_val_t other_v)
{
	if (v->implementation->type != other_v->implementation->type) {
		return 0;
	}

	if (v->implementation->add == NULL) {
		return 0;
	}

	return v->implementation->add(v->val, other_v->val);
}

int cli_val_sub(cli_val_t v, cli_val_t other_v)
{
	if (v->implementation->type != other_v->implementation->type) {
		return 0;
	}

	if (v->implementation->sub == NULL) {
		return 0;
	}

	return v->implementation->sub(v->val, other_v->val);
}

int cli_val_cmp(cli_val_t v, cli_val_t other_v)
{
	if (v->implementation->type != other_v->implementation->type) {
		return 0;
	}

	if (v->implementation->cmp == NULL) {
		return 0;
	}

	return v->implementation->cmp(v->val, other_v->val);
}

int cli_val_print(cli_val_t v, FILE *f)
{
	if (v->implementation->print == NULL) {
		return 0;
	}

	return v->implementation->print(v->val, f);
}

int cli_val_scan(cli_val_t v, FILE *f)
{
	if (v->implementation->scan == NULL) {
		return 0;
	}

	return v->implementation->scan(v->val, f);
}

int cli_val_parse_text(cli_val_t v, const char *s)
{
	if (v->implementation->parse_text == NULL) {
		return 0;
	}

	return v->implementation->parse_text(v->val, s);
}

int cli_val_parse_binary(cli_val_t v, const void *b, size_t length)
{
	if (v->implementation->parse_binary == NULL) {
		return 0;
	}

	return v->implementation->parse_binary(v->val, b, length);
}

cli_val_t cli_val_nil(void)
{
	return nil;
}
