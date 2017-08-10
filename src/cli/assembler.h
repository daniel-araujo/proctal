#ifndef CLI_ASSEMBLER_H
#define CLI_ASSEMBLER_H

#include <stdlib.h>

/*
 * Supported CPU architectures.
 */
enum cli_assembler_architecture {
	CLI_ASSEMBLER_ARCHITECTURE_X86,
	CLI_ASSEMBLER_ARCHITECTURE_X86_64,
	CLI_ASSEMBLER_ARCHITECTURE_ARM,
	CLI_ASSEMBLER_ARCHITECTURE_AARCH64,
};

/*
 * Supported assembly syntaxes.
 */
enum cli_assembler_syntax {
	CLI_ASSEMBLER_SYNTAX_INTEL,
	CLI_ASSEMBLER_SYNTAX_ATT,
};

#if PROCTAL_CPU_ARCHITECTURE_X86
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_X86
#elif PROCTAL_CPU_ARCHITECTURE_X86_64
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_X86_64
#elif PROCTAL_CPU_ARCHITECTURE_ARM
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_ARM
#elif PROCTAL_CPU_ARCHITECTURE_AARCH64
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_AARCH64
#else
	// Unknown CPU architecture. Define macro with some random architecture
	// to keep code simple.
	#define CLI_ASSEMBLER_ARCHITECTURE_DEFAULT CLI_ASSEMBLER_ARCHITECTURE_X86_64
#endif

#define CLI_ASSEMBLER_SYNTAX_DEFAULT CLI_ASSEMBLER_SYNTAX_INTEL

/*
 * The assembler struct. This keeps track of a lot of information that is
 * needed for compiling and decompiling instructions.
 */
struct cli_assembler {
	// CPU architecture.
	enum cli_assembler_architecture arch;

	// Assembly syntax.
	enum cli_assembler_syntax syntax;

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
	assembler->arch = CLI_ASSEMBLER_ARCHITECTURE_DEFAULT;
	assembler->syntax = CLI_ASSEMBLER_SYNTAX_DEFAULT;
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
inline void cli_assembler_architecture_set(struct cli_assembler *assembler, enum cli_assembler_architecture arch)
{
	assembler->arch = arch;
}

/*
 * Sets the assembly syntax.
 */
inline void cli_assembler_syntax_set(struct cli_assembler *assembler, enum cli_assembler_syntax syntax)
{
	assembler->syntax = syntax;
}

/*
 * Sets the address where the instruction is located in memory.
 */
inline void cli_assembler_address_set(struct cli_assembler *assembler, void *address)
{
	assembler->address = address;
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
