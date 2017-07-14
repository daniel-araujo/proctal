#include "cli/val/instruction.h"

struct cs_parameters {
	enum cs_arch arch;
	enum cs_mode mode;
};

static int init_cs_parameters(struct cli_val_instruction *v, struct cs_parameters *params)
{
	switch (v->attr.arch) {
	case CLI_VAL_INSTRUCTION_ARCH_X86:
		params->arch = CS_ARCH_X86;
		params->mode = CS_MODE_32;
		return 1;

	case CLI_VAL_INSTRUCTION_ARCH_X86_64:
		params->arch = CS_ARCH_X86;
		params->mode = CS_MODE_64;
		return 1;

	case CLI_VAL_INSTRUCTION_ARCH_ARM:
		params->arch = CS_ARCH_ARM;
		params->mode = CS_MODE_ARM;
		return 1;

	case CLI_VAL_INSTRUCTION_ARCH_AARCH64:
		params->arch = CS_ARCH_ARM64;
		params->mode = 0;
		return 1;

	default:
		// Not supported.
		return 0;
	}
}

static int set_cs_syntax(struct cli_val_instruction *v, csh handle)
{
	switch (v->attr.syntax) {
	case CLI_VAL_INSTRUCTION_SYNTAX_INTEL:
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
		return 1;

	case CLI_VAL_INSTRUCTION_SYNTAX_ATT:
		cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		return 1;

	default:
		// Not supported.
		return 0;
	}
}

struct ks_parameters {
	enum ks_arch arch;
	enum ks_mode mode;
};

static int init_ks_parameters(struct cli_val_instruction *v, struct ks_parameters *params)
{
	switch (v->attr.arch) {
	case CLI_VAL_INSTRUCTION_ARCH_X86:
		params->arch = KS_ARCH_X86;
		params->mode = KS_MODE_32;
		return 1;

	case CLI_VAL_INSTRUCTION_ARCH_X86_64:
		params->arch = KS_ARCH_X86;
		params->mode = KS_MODE_64;
		return 1;

	case CLI_VAL_INSTRUCTION_ARCH_ARM:
		params->arch = KS_ARCH_ARM;
		params->mode = KS_MODE_ARM;
		return 1;

	case CLI_VAL_INSTRUCTION_ARCH_AARCH64:
		params->arch = KS_ARCH_ARM64;
		params->mode = 0;
		return 1;

	default:
		// Not supported.
		return 0;
	}
}

static int set_ks_syntax(struct cli_val_instruction *v, ks_engine *handle)
{
	switch (v->attr.syntax) {
	case CLI_VAL_INSTRUCTION_SYNTAX_INTEL:
		ks_option(handle, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
		return 1;

	case CLI_VAL_INSTRUCTION_SYNTAX_ATT:
		ks_option(handle, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
		return 1;

	default:
		// Not supported.
		return 0;
	}
}

void cli_val_instruction_attr_init(struct cli_val_instruction_attr *a);

void cli_val_instruction_attr_arch_set(
	struct cli_val_instruction_attr *a,
	enum cli_val_instruction_arch arch);

void cli_val_instruction_attr_syntax_set(
	struct cli_val_instruction_attr *a,
	enum cli_val_instruction_syntax syntax);

void cli_val_instruction_attr_deinit(struct cli_val_instruction_attr *a);

struct cli_val_instruction *cli_val_instruction_create(struct cli_val_instruction_attr *a);

void cli_val_instruction_destroy(struct cli_val_instruction *v);

void cli_val_instruction_address_set(struct cli_val_instruction *v, void *addr);

void *cli_val_instruction_raw(struct cli_val_instruction *v);

size_t cli_val_instruction_sizeof(struct cli_val_instruction *v);

int cli_val_instruction_print(struct cli_val_instruction *v, FILE *f);

struct cli_val_instruction *cli_val_instruction_create_clone(struct cli_val_instruction *other_v);

int cli_val_instruction_parse_bin(struct cli_val_instruction *v, const char *s, size_t length)
{
	if (v->insn) {
		cs_free(v->insn, 1);
		v->insn = NULL;
	}

	struct cs_parameters params;

	if (!init_cs_parameters(v, &params)) {
		return 0;
	}

	csh handle;

	if (cs_open(params.arch, params.mode, &handle) != CS_ERR_OK) {
		return 0;
	}

	if (!set_cs_syntax(v, handle)) {
		return 0;
	}

	int count = cs_disasm(handle, (const unsigned char *) s, length, (unsigned long int) v->addr, 1, &v->insn);

	cs_close(&handle);

	if (count == 0) {
		return 0;
	}

	return v->insn->size;
}

int cli_val_instruction_parse(struct cli_val_instruction *v, const char *s)
{
	if (v->insn) {
		cs_free(v->insn, 1);
		v->insn = NULL;
	}

	// The value structure was programmed to hold a reference to a capstone
	// disassembled instruction because it conveniently provides all the
	// information we care about. To remain compatible with existing code,
	// we're going to assemble the code with keystone and then disassemble
	// the result with capstone so as to keep the remaining code as is.
	// Also, it ensures we only parse the first instruction that shows up
	// and ignore the rest.

	struct ks_parameters params;

	if (!init_ks_parameters(v, &params)) {
		return 0;
	}

	ks_engine *ks;

	size_t count;
	unsigned char *encode;
	size_t size;

	if (ks_open(params.arch, params.mode, &ks) != KS_ERR_OK) {
		return 0;
	}

	if (!set_ks_syntax(v, ks)) {
		return 0;
	}

	if (ks_asm(ks, s, 0, &encode, &size, &count) != KS_ERR_OK) {
		ks_close(ks);
		return 0;
	}

	int parse_bin = cli_val_instruction_parse_bin(v, (const char *) encode, size);

	ks_free(encode);
	ks_close(ks);

	return parse_bin ? 1 : 0;
}
