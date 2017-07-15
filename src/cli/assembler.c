#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>
#include <keystone/keystone.h>
#include <assert.h>
#include <errno.h>

#include "cli/assembler.h"
#include "cli/parser.h"

struct cs_parameters {
	enum cs_arch arch;
	enum cs_mode mode;
};

struct ks_parameters {
	enum ks_arch arch;
	enum ks_mode mode;
};

static int init_cs_parameters(struct cli_assembler *assembler, struct cs_parameters *params)
{
	switch (assembler->arch) {
	case CLI_ASSEMBLER_ARCH_X86:
		params->arch = CS_ARCH_X86;
		params->mode = CS_MODE_32;
		return 1;

	case CLI_ASSEMBLER_ARCH_X86_64:
		params->arch = CS_ARCH_X86;
		params->mode = CS_MODE_64;
		return 1;

	case CLI_ASSEMBLER_ARCH_ARM:
		params->arch = CS_ARCH_ARM;
		params->mode = CS_MODE_ARM;
		return 1;

	case CLI_ASSEMBLER_ARCH_AARCH64:
		params->arch = CS_ARCH_ARM64;
		params->mode = 0;
		return 1;

	default:
		// Not supported.
		return 0;
	}
}

static int set_cs_syntax(struct cli_assembler *assembler, csh cs)
{
	switch (assembler->syntax) {
	case CLI_ASSEMBLER_SYNTAX_INTEL:
		cs_option(cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
		return 1;

	case CLI_ASSEMBLER_SYNTAX_ATT:
		cs_option(cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
		return 1;

	default:
		// Not supported.
		return 0;
	}
}

static int init_ks_parameters(struct cli_assembler *assembler, struct ks_parameters *params)
{
	switch (assembler->arch) {
	case CLI_ASSEMBLER_ARCH_X86:
		params->arch = KS_ARCH_X86;
		params->mode = KS_MODE_32;
		return 1;

	case CLI_ASSEMBLER_ARCH_X86_64:
		params->arch = KS_ARCH_X86;
		params->mode = KS_MODE_64;
		return 1;

	case CLI_ASSEMBLER_ARCH_ARM:
		params->arch = KS_ARCH_ARM;
		params->mode = KS_MODE_ARM;
		return 1;

	case CLI_ASSEMBLER_ARCH_AARCH64:
		params->arch = KS_ARCH_ARM64;
		params->mode = 0;
		return 1;

	default:
		// Not supported.
		return 0;
	}
}

static int set_ks_syntax(struct cli_assembler *assembler, ks_engine *ks)
{
	switch (assembler->syntax) {
	case CLI_ASSEMBLER_SYNTAX_INTEL:
		ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
		return 1;

	case CLI_ASSEMBLER_SYNTAX_ATT:
		ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
		return 1;

	default:
		// Not supported.
		return 0;
	}
}

static void cli_assembler_error_message_set(struct cli_assembler *assembler, const char *message)
{
	assembler->error_message = message;
}

static size_t limit_to_one_instruction(const char *assembly, size_t assembly_size)
{
	if (assembly_size == 0) {
		return 0;
	}

	return cli_parse_skip_until_chars2(assembly, assembly_size, "\n;");
}

void cli_assembler_init(struct cli_assembler *assembler);

void cli_assembler_deinit(struct cli_assembler *assembler);

void cli_assembler_arch_set(struct cli_assembler *assembler, enum cli_assembler_arch arch);

void cli_assembler_syntax_set(struct cli_assembler *assembler, enum cli_assembler_syntax syntax);

void cli_assembler_address_set(struct cli_assembler *assembler, void *address);

const char *cli_assembler_error_message(struct cli_assembler *assembler);

int cli_assembler_compile(struct cli_assembler *assembler, const char *assembly, size_t assembly_size, struct cli_assembler_compile_result *result)
{
	int ret = 0;

	assembly_size = limit_to_one_instruction(assembly, assembly_size);

	if (assembly_size == 0) {
		cli_assembler_error_message_set(assembler, "No instruction given.");
		goto exit0;
	}

	// We're going to create a NUL terminated string because that's all
	// that Keystone accepts.
	char *zassembly = malloc(assembly_size + 1);
	zassembly[assembly_size] = '\0';

	if (zassembly == NULL) {
		cli_assembler_error_message_set(assembler, strerror(errno));
		goto exit0;
	}

	memcpy(zassembly, assembly, assembly_size);

	struct ks_parameters params;

	if (!init_ks_parameters(assembler, &params)) {
		cli_assembler_error_message_set(assembler, "Parameters error.");
		goto exit1;
	}

	ks_engine *ks;

	if (ks_open(params.arch, params.mode, &ks) != KS_ERR_OK) {
		cli_assembler_error_message_set(assembler, "Parameters error.");
		goto exit1;
	}

	if (!set_ks_syntax(assembler, ks)) {
		cli_assembler_error_message_set(assembler, "Syntax not supported.");
		goto exit2;
	}

	size_t count;
	unsigned char *encoding;
	size_t encoding_size;

	int ks_result = ks_asm(
		ks,
		zassembly,
		(uint64_t) assembler->address,
		(unsigned char **) &encoding,
		&encoding_size,
		&count);

	if (ks_result != KS_ERR_OK) {
		cli_assembler_error_message_set(assembler, ks_strerror(ks_errno(ks)));
		goto exit2;
	}

	if (count == 0) {
		cli_assembler_error_message_set(assembler, "No assembly statement found.");
		goto exit2;
	}

	// Only expecting to compile a single instruction.
	assert(count == 1);

	char *bytecode = malloc(encoding_size);

	if (bytecode == NULL) {
		cli_assembler_error_message_set(assembler, strerror(errno));
		goto exit3;
	}

	memcpy(bytecode, encoding, encoding_size);

	result->read = assembly_size;
	result->bytecode = bytecode;
	result->bytecode_size = encoding_size;

	ret = 1;
exit3:
	ks_free(encoding);
exit2:
	ks_close(ks);
exit1:
	free(zassembly);
exit0:
	return ret;
}

void cli_assembler_compile_dispose(struct cli_assembler_compile_result *result)
{
	free(result->bytecode);
}

int cli_assembler_decompile(struct cli_assembler *assembler, const char *bytecode, size_t bytecode_size, struct cli_assembler_decompile_result *result)
{
	int ret = 0;

	struct cs_parameters params;

	if (!init_cs_parameters(assembler, &params)) {
		cli_assembler_error_message_set(assembler, "Parameters error.");
		goto exit0;
	}

	csh cs;

	if (cs_open(params.arch, params.mode, &cs) != CS_ERR_OK) {
		cli_assembler_error_message_set(assembler, "Parameters error.");
		goto exit0;
	}

	if (!set_cs_syntax(assembler, cs)) {
		cli_assembler_error_message_set(assembler, "Syntax not supported.");
		goto exit1;
	}

	cs_insn *insn;
	int count = cs_disasm(
		cs,
		(const unsigned char *) bytecode,
		bytecode_size,
		(uint64_t) assembler->address,
		1,
		&insn);

	if (count == 0) {
		cli_assembler_error_message_set(assembler, cs_strerror(cs_errno(cs)));
		goto exit1;
	}

	size_t mnemonic_size = strlen(insn->mnemonic);
	size_t op_size = strlen(insn->op_str);

	size_t assembly_size = mnemonic_size + (op_size ? 1 + op_size : 0);
	char *assembly = malloc(assembly_size);

	if (assembly == NULL) {
		cli_assembler_error_message_set(assembler, strerror(errno));
		goto exit2;
	}

	memcpy(assembly, insn->mnemonic, mnemonic_size);

	if (op_size) {
		assembly[mnemonic_size] = '\t';
		memcpy(assembly + mnemonic_size + 1, insn->op_str, op_size);
	}

	result->read = insn->size;
	result->assembly = assembly;
	result->assembly_size = assembly_size;

	ret = 1;
exit2:
	cs_free(insn, count);
exit1:
	cs_close(&cs);
exit0:
	return ret;
}

void cli_assembler_decompile_dispose(struct cli_assembler_decompile_result *result)
{
	free(result->assembly);
}
