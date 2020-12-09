#ifndef CLI_ASSEMBLER_H
#define CLI_ASSEMBLER_H

#include <stdlib.h>

#include "config.h"

/*
 * CPU architectures.
 */
enum cli_assembler_architecture {
	CLI_ASSEMBLER_ARCHITECTURE_X86,
	CLI_ASSEMBLER_ARCHITECTURE_ARM,
	CLI_ASSEMBLER_ARCHITECTURE_SPARC,
	CLI_ASSEMBLER_ARCHITECTURE_POWERPC,
	CLI_ASSEMBLER_ARCHITECTURE_MIPS,
};

/*
 * x86 modes.
 */
enum cli_assembler_x86_mode {
	CLI_ASSEMBLER_X86_MODE_16,
	CLI_ASSEMBLER_X86_MODE_32,
	CLI_ASSEMBLER_X86_MODE_64,
};

/*
 * x86 syntaxes.
 */
enum cli_assembler_x86_syntax {
	CLI_ASSEMBLER_X86_SYNTAX_INTEL,
	CLI_ASSEMBLER_X86_SYNTAX_ATT,
};

/*
 * ARM modes.
 */
enum cli_assembler_arm_mode {
	CLI_ASSEMBLER_ARM_MODE_A32,
	CLI_ASSEMBLER_ARM_MODE_T32,
	CLI_ASSEMBLER_ARM_MODE_A64,
};

/*
 * SPARC modes.
 */
enum cli_assembler_sparc_mode {
	CLI_ASSEMBLER_SPARC_MODE_32,
	CLI_ASSEMBLER_SPARC_MODE_64,
	CLI_ASSEMBLER_SPARC_MODE_V9,
};

/*
 * PowerPC modes.
 */
enum cli_assembler_powerpc_mode {
	CLI_ASSEMBLER_POWERPC_MODE_32,
	CLI_ASSEMBLER_POWERPC_MODE_64,
	CLI_ASSEMBLER_POWERPC_MODE_QPX,
};

/*
 * MIPS modes.
 */
enum cli_assembler_mips_mode {
	CLI_ASSEMBLER_MIPS_MODE_MICRO,
	CLI_ASSEMBLER_MIPS_MODE_3,
	CLI_ASSEMBLER_MIPS_MODE_32R6,
	CLI_ASSEMBLER_MIPS_MODE_32,
	CLI_ASSEMBLER_MIPS_MODE_64,
};

/*
 * Endianness.
 */
enum cli_assembler_endianness {
	CLI_ASSEMBLER_ENDIANNESS_LITTLE,
	CLI_ASSEMBLER_ENDIANNESS_BIG,
};

/*
 * Default values.
 */
#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_X86
#define CLI_ASSEMBLER_X86_MODE_DEFAULT CLI_ASSEMBLER_X86_MODE_64
#define CLI_ASSEMBLER_X86_SYNTAX_DEFAULT CLI_ASSEMBLER_X86_SYNTAX_INTEL
#define CLI_ASSEMBLER_ARM_MODE_DEFAULT CLI_ASSEMBLER_ARM_MODE_A64
#define CLI_ASSEMBLER_POWERPC_MODE_DEFAULT CLI_ASSEMBLER_POWERPC_MODE_64
#define CLI_ASSEMBLER_SPARC_MODE_DEFAULT CLI_ASSEMBLER_SPARC_MODE_64
#define CLI_ASSEMBLER_MIPS_MODE_DEFAULT CLI_ASSEMBLER_MIPS_MODE_64

#ifdef PROCTAL_CPU_ARCHITECTURE_X86

	#undef CLI_ASSEMBLER_ARCHITECTURE_DEFAULT
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_X86

	#ifdef PROCTAL_CPU_ARCHITECTURE_X86_MODE_32

		#undef CLI_ASSEMBLER_X86_MODE_DEFAULT
		#define CLI_ASSEMBLER_X86_MODE_DEFAULT CLI_ASSEMBLER_X86_MODE_32

	#elif defined PROCTAL_CPU_ARCHITECTURE_X86_MODE_64

		#undef CLI_ASSEMBLER_X86_MODE_DEFAULT
		#define CLI_ASSEMBLER_X86_MODE_DEFAULT CLI_ASSEMBLER_X86_MODE_64

	#endif

#elif defined PROCTAL_CPU_ARCHITECTURE_ARM

	#undef CLI_ASSEMBLER_ARCHITECTURE_DEFAULT
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_ARM

	#ifdef PROCTAL_CPU_ARCHITECTURE_ARM_MODE_A32

		#undef CLI_ASSEMBLER_ARM_MODE_DEFAULT
		#define CLI_ASSEMBLER_ARM_MODE_DEFAULT CLI_ASSEMBLER_ARM_MODE_A32

	#elif defined PROCTAL_CPU_ARCHITECTURE_ARM_MODE_A64

		#undef CLI_ASSEMBLER_ARM_MODE_DEFAULT
		#define CLI_ASSEMBLER_ARM_MODE_DEFAULT CLI_ASSEMBLER_ARM_MODE_A64

	#endif

#elif defined PROCTAL_CPU_ARCHITECTURE_SPARC

	#undef CLI_ASSEMBLER_ARCHITECTURE_DEFAULT
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_SPARC

#elif defined PROCTAL_CPU_ARCHITECTURE_POWERPC

	#undef CLI_ASSEMBLER_ARCHITECTURE_DEFAULT
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_POWERPC

#elif defined PROCTAL_CPU_ARCHITECTURE_MIPS

	#undef CLI_ASSEMBLER_ARCHITECTURE_DEFAULT
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_MIPS

#endif

#ifdef PROCTAL_INTEGER_ENDIANNESS_LITTLE

	#define CLI_ASSEMBLER_ENDIANNESS_DEFAULT CLI_ASSEMBLER_ENDIANNESS_LITTLE

#elif defined PROCTAL_INTEGER_ENDIANNESS_BIG

	#define CLI_ASSEMBLER_ENDIANNESS_DEFAULT CLI_ASSEMBLER_ENDIANNESS_BIG

#else

	#error "Unknown integer endianness."

#endif

/*
 * The assembler struct. This keeps track of a lot of information that is
 * needed for compiling and decompiling instructions.
 */
struct cli_assembler {
	// CPU architecture.
	enum cli_assembler_architecture architecture;

	// Endianness.
	enum cli_assembler_endianness endianness;

	// x86 mode.
	enum cli_assembler_x86_mode x86_mode;

	// x86 syntax.
	enum cli_assembler_x86_syntax x86_syntax;

	// ARM mode.
	enum cli_assembler_arm_mode arm_mode;

	// SPARC mode.
	enum cli_assembler_sparc_mode sparc_mode;

	// PowerPC mode.
	enum cli_assembler_powerpc_mode powerpc_mode;

	// MIPS mode.
	enum cli_assembler_mips_mode mips_mode;

	// Address where the instruction is located in memory.
	// This information is important when calculating the
	// destination address of a relative jump instruction
	// supported by certain architectures.
	void *address;

	// A message that describes the last error that occurred.
	const char *error_message;
};

/*
 * The result of compiling.
 */
struct cli_assembler_compile_result {
	// How much of the input was read.
	size_t read;

	// Bytecode.
	char *bytecode;

	// Bytecode size.
	size_t bytecode_size;
};

/*
 * The result of decompiling.
 */
struct cli_assembler_decompile_result {
	// How much of the input was read.
	size_t read;

	// Assembly language instruction.
	char *assembly;

	// Size of the assembly language instruction.
	size_t assembly_size;
};

/*
 * Initializes the assembler.
 *
 * Call cli_assembler_deinit to deinitialize.
 */
inline void cli_assembler_init(struct cli_assembler *assembler)
{
	assembler->architecture = CLI_ASSEMBLER_ARCHITECTURE_DEFAULT;
	assembler->endianness = CLI_ASSEMBLER_ENDIANNESS_DEFAULT;
	assembler->x86_mode = CLI_ASSEMBLER_X86_MODE_DEFAULT;
	assembler->x86_syntax = CLI_ASSEMBLER_X86_SYNTAX_DEFAULT;
	assembler->arm_mode = CLI_ASSEMBLER_ARM_MODE_DEFAULT;
	assembler->powerpc_mode = CLI_ASSEMBLER_POWERPC_MODE_DEFAULT;
	assembler->sparc_mode = CLI_ASSEMBLER_SPARC_MODE_DEFAULT;
	assembler->mips_mode = CLI_ASSEMBLER_MIPS_MODE_DEFAULT;
	assembler->address = NULL;
	assembler->error_message = NULL;
}

/*
 * Deinitializes the assembler.
 */
inline void cli_assembler_deinit(struct cli_assembler *assembler)
{
}

/*
 * Sets the CPU architecture.
 */
inline void cli_assembler_architecture_set(struct cli_assembler *assembler, enum cli_assembler_architecture architecture)
{
	assembler->architecture = architecture;
}

/*
 * Sets endianness
 */
inline void cli_assembler_endianness_set(struct cli_assembler *assembler, enum cli_assembler_endianness endianness)
{
	assembler->endianness = endianness;
}

/*
 * Sets x86 mode.
 */
inline void cli_assembler_x86_mode_set(struct cli_assembler *assembler, enum cli_assembler_x86_mode x86_mode)
{
	assembler->x86_mode = x86_mode;
}

/*
 * Sets the syntax for x86.
 */
inline void cli_assembler_x86_syntax_set(struct cli_assembler *assembler, enum cli_assembler_x86_syntax x86_syntax)
{
	assembler->x86_syntax = x86_syntax;
}

/*
 * Sets arm mode.
 */
inline void cli_assembler_arm_mode_set(struct cli_assembler *assembler, enum cli_assembler_arm_mode arm_mode)
{
	assembler->arm_mode = arm_mode;
}

/*
 * Sets sparc mode.
 */
inline void cli_assembler_sparc_mode_set(struct cli_assembler *assembler, enum cli_assembler_sparc_mode sparc_mode)
{
	assembler->sparc_mode = sparc_mode;
}

/*
 * Sets powerpc mode.
 */
inline void cli_assembler_powerpc_mode_set(struct cli_assembler *assembler, enum cli_assembler_powerpc_mode powerpc_mode)
{
	assembler->powerpc_mode = powerpc_mode;
}

/*
 * Sets mips mode.
 */
inline void cli_assembler_mips_mode_set(struct cli_assembler *assembler, enum cli_assembler_mips_mode mips_mode)
{
	assembler->mips_mode = mips_mode;
}

/*
 * Sets the address where the instruction is located in memory.
 */
inline void cli_assembler_address_set(struct cli_assembler *assembler, void *address)
{
	assembler->address = address;
}

/*
 * Gets the address where the instruction is located in memory.
 */
inline void* cli_assembler_address(struct cli_assembler *assembler)
{
	return assembler->address;
}

/*
 * Returns a pointer to a message that describes the last error.
 *
 * If no error has happened, this will return NULL.
 */
inline const char *cli_assembler_error_message(struct cli_assembler *assembler)
{
	return assembler->error_message;
}

/*
 * Assembles an assembly instruction into bytecode.
 *
 * Returns 1 on success and 0 on failure.
 *
 * If the compilation is successful, the result must later be disposed with a
 * call to cli_assembler_compile_dispose.
 */
int cli_assembler_compile(struct cli_assembler *assembler, const char *assembly, size_t assembly_size, struct cli_assembler_compile_result *result);

/*
 * Disposes the result of a compilation.
 */
void cli_assembler_compile_dispose(struct cli_assembler_compile_result *result);

/*
 * Decompiles bytecode into an assembly instruction.
 *
 * Returns 1 on success and 0 on failure.
 *
 * If the decompilation is successful, the result must later be disposed with a
 * call to cli_assembler_decompile_dispose.
 */
int cli_assembler_decompile(struct cli_assembler *assembler, const char *bytecode, size_t bytecode_size, struct cli_assembler_decompile_result *result);

/*
 * Disposes the result of a decompilation.
 */
void cli_assembler_decompile_dispose(struct cli_assembler_decompile_result *result);

#endif /* CLI_ASSEMBLER_H */
