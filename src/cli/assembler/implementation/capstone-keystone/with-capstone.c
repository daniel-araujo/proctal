#include <stdlib.h>
#include <string.h>
#include <capstone/capstone.h>
#include <assert.h>
#include <errno.h>

#include "cli/assembler/internal.h"
#include "cli/assembler/implementation.h"

struct cs_parameters {
	enum cs_arch arch;
	enum cs_mode mode;
};

static int init_cs_parameters(struct cli_assembler *assembler, struct cs_parameters *params)
{
	switch (assembler->endianness) {
	case CLI_ASSEMBLER_ENDIANNESS_LITTLE:
		params->mode = CS_MODE_LITTLE_ENDIAN;
		break;

	case CLI_ASSEMBLER_ENDIANNESS_BIG:
		params->mode = CS_MODE_BIG_ENDIAN;
		break;

	default:
		// Not supported.
		return 0;
	}

	switch (assembler->architecture) {
	case CLI_ASSEMBLER_ARCHITECTURE_X86:
		params->arch = CS_ARCH_X86;

		switch (assembler->x86_mode) {
		case CLI_ASSEMBLER_X86_MODE_16:
			params->mode |= CS_MODE_16;
			return 1;

		case CLI_ASSEMBLER_X86_MODE_32:
			params->mode |= CS_MODE_32;
			return 1;

		case CLI_ASSEMBLER_X86_MODE_64:
			params->mode |= CS_MODE_64;
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	case CLI_ASSEMBLER_ARCHITECTURE_ARM:
		switch (assembler->arm_mode) {
		case CLI_ASSEMBLER_ARM_MODE_A32:
			params->arch = CS_ARCH_ARM;
			params->mode |= CS_MODE_ARM;
			return 1;

		case CLI_ASSEMBLER_ARM_MODE_T32:
			params->arch = CS_ARCH_ARM;
			params->mode |= CS_MODE_THUMB;
			return 1;

		case CLI_ASSEMBLER_ARM_MODE_A64:
			params->arch = CS_ARCH_ARM64;
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	case CLI_ASSEMBLER_ARCHITECTURE_SPARC:
		params->arch = CS_ARCH_SPARC;

		switch (assembler->sparc_mode) {
		case CLI_ASSEMBLER_SPARC_MODE_32:
		case CLI_ASSEMBLER_SPARC_MODE_64:
			return 1;

		case CLI_ASSEMBLER_SPARC_MODE_V9:
			params->mode |= CS_MODE_V9;
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	case CLI_ASSEMBLER_ARCHITECTURE_POWERPC:
		params->arch = CS_ARCH_PPC;

		switch (assembler->powerpc_mode) {
		case CLI_ASSEMBLER_POWERPC_MODE_32:
			return 1;

		case CLI_ASSEMBLER_POWERPC_MODE_64:
			params->mode |= CS_MODE_64;
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	case CLI_ASSEMBLER_ARCHITECTURE_MIPS:
		params->arch = CS_ARCH_MIPS;

		switch (assembler->mips_mode) {
		case CLI_ASSEMBLER_MIPS_MODE_MICRO:
			params->mode |= CS_MODE_MICRO;
			return 1;

		case CLI_ASSEMBLER_MIPS_MODE_3:
			params->mode |= CS_MODE_MIPS3;
			return 1;

		case CLI_ASSEMBLER_MIPS_MODE_32R6:
			params->mode |= CS_MODE_MIPS32R6;
			return 1;

		case CLI_ASSEMBLER_MIPS_MODE_32:
			params->mode |= CS_MODE_MIPS32;
			return 1;

		case CLI_ASSEMBLER_MIPS_MODE_64:
			params->mode |= CS_MODE_MIPS64;
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	default:
		// Not supported.
		return 0;
	}
}

static int set_cs_syntax(struct cli_assembler *assembler, csh cs)
{
	switch (assembler->architecture) {
	case CLI_ASSEMBLER_ARCHITECTURE_X86:
		switch (assembler->x86_syntax) {
		case CLI_ASSEMBLER_X86_SYNTAX_INTEL:
			cs_option(cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_INTEL);
			return 1;

		case CLI_ASSEMBLER_X86_SYNTAX_ATT:
			cs_option(cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	case CLI_ASSEMBLER_ARCHITECTURE_POWERPC:
		cs_option(cs, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME);
		return 1;

	default:
		// Use default.
		return 1;
	}
}

int cli_assembler_implementation_decompile(struct cli_assembler *assembler, const char *bytecode, size_t bytecode_size, struct cli_assembler_decompile_result *result)
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

void cli_assembler_implementation_decompile_dispose(struct cli_assembler_decompile_result *result)
{
	free(result->assembly);
}
