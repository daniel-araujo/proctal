#include <stdlib.h>
#include <string.h>
#include <keystone/keystone.h>
#include <assert.h>
#include <errno.h>

#include "cli/assembler/internal.h"
#include "cli/assembler/implementation.h"

struct ks_parameters {
	enum ks_arch arch;
	enum ks_mode mode;
};

static int init_ks_parameters(struct cli_assembler *assembler, struct ks_parameters *params)
{
	switch (assembler->endianness) {
	case CLI_ASSEMBLER_ENDIANNESS_LITTLE:
		params->mode = KS_MODE_LITTLE_ENDIAN;
		break;

	case CLI_ASSEMBLER_ENDIANNESS_BIG:
		params->mode = KS_MODE_BIG_ENDIAN;
		break;

	default:
		// Not supported.
		return 0;
	}

	switch (assembler->architecture) {
	case CLI_ASSEMBLER_ARCHITECTURE_X86:
		params->arch = KS_ARCH_X86;

		switch (assembler->x86_mode) {
		case CLI_ASSEMBLER_X86_MODE_16:
			params->mode |= KS_MODE_16;
			return 1;

		case CLI_ASSEMBLER_X86_MODE_32:
			params->mode |= KS_MODE_32;
			return 1;

		case CLI_ASSEMBLER_X86_MODE_64:
			params->mode |= KS_MODE_64;
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	case CLI_ASSEMBLER_ARCHITECTURE_ARM:
		switch (assembler->arm_mode) {
		case CLI_ASSEMBLER_ARM_MODE_A32:
			params->arch = KS_ARCH_ARM;
			params->mode |= KS_MODE_ARM;
			return 1;

		case CLI_ASSEMBLER_ARM_MODE_T32:
			params->arch = KS_ARCH_ARM;
			params->mode |= KS_MODE_THUMB;
			return 1;

		case CLI_ASSEMBLER_ARM_MODE_A64:
			params->arch = KS_ARCH_ARM64;
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	case CLI_ASSEMBLER_ARCHITECTURE_SPARC:
		params->arch = KS_ARCH_SPARC;

		switch (assembler->sparc_mode) {
		case CLI_ASSEMBLER_SPARC_MODE_32:
			params->mode |= KS_MODE_SPARC32;
			return 1;

		case CLI_ASSEMBLER_SPARC_MODE_64:
			params->mode |= KS_MODE_SPARC64;
			return 1;

		case CLI_ASSEMBLER_SPARC_MODE_V9:
			params->mode |= KS_MODE_V9;
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	case CLI_ASSEMBLER_ARCHITECTURE_POWERPC:
		params->arch = KS_ARCH_PPC;

		switch (assembler->powerpc_mode) {
		case CLI_ASSEMBLER_POWERPC_MODE_32:
			params->mode |= KS_MODE_PPC32;
			return 1;

		case CLI_ASSEMBLER_POWERPC_MODE_64:
			params->mode |= KS_MODE_PPC64;
			return 1;

		case CLI_ASSEMBLER_POWERPC_MODE_QPX:
			params->mode |= KS_MODE_QPX;
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	case CLI_ASSEMBLER_ARCHITECTURE_MIPS:
		params->arch = KS_ARCH_MIPS;

		switch (assembler->mips_mode) {
		case CLI_ASSEMBLER_MIPS_MODE_MICRO:
			params->mode |= KS_MODE_MICRO;
			return 1;

		case CLI_ASSEMBLER_MIPS_MODE_3:
			params->mode |= KS_MODE_MIPS3;
			return 1;

		case CLI_ASSEMBLER_MIPS_MODE_32R6:
			params->mode |= KS_MODE_MIPS32R6;
			return 1;

		case CLI_ASSEMBLER_MIPS_MODE_32:
			params->mode |= KS_MODE_MIPS32;
			return 1;

		case CLI_ASSEMBLER_MIPS_MODE_64:
			params->mode |= KS_MODE_MIPS64;
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

static int set_ks_syntax(struct cli_assembler *assembler, ks_engine *ks)
{
	switch (assembler->architecture) {
	case CLI_ASSEMBLER_ARCHITECTURE_X86:
		switch (assembler->x86_syntax) {
		case CLI_ASSEMBLER_X86_SYNTAX_INTEL:
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_INTEL);
			return 1;

		case CLI_ASSEMBLER_X86_SYNTAX_ATT:
			ks_option(ks, KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
			return 1;

		default:
			// Not supported.
			return 0;
		}
		break;

	default:
		// Use default.
		return 1;
	}
}

int cli_assembler_implementation_compile(struct cli_assembler *assembler, const char *assembly, size_t assembly_size, struct cli_assembler_compile_result *result)
{
	int ret = 0;

	assembly_size = cli_assembler_limit_to_one_instruction(assembly, assembly_size);

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

void cli_assembler_implementation_compile_dispose(struct cli_assembler_compile_result *result)
{
	free(result->bytecode);
}
