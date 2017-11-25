<?php

$parsers = [
	[
		"name" => "val_type",
		"type" => "enum cli_val_type",
		"values" => [
			"byte" => "CLI_VAL_TYPE_BYTE",
			"integer" => "CLI_VAL_TYPE_INTEGER",
			"ieee754" => "CLI_VAL_TYPE_IEEE754",
			"text" => "CLI_VAL_TYPE_TEXT",
			"address" => "CLI_VAL_TYPE_ADDRESS",
			"x86" => "CLI_VAL_TYPE_X86",
			"arm" => "CLI_VAL_TYPE_ARM",
		],
	],
	[
		"name" => "val_integer_endianness",
		"type" => "enum cli_val_integer_endianness",
		"values" => [
			"little" => "CLI_VAL_INTEGER_ENDIANNESS_LITTLE",
			"big" => "CLI_VAL_INTEGER_ENDIANNESS_BIG",
		],
	],
	[
		"name" => "val_integer_bits",
		"type" => "enum cli_val_integer_bits",
		"values" => [
			"8" => "CLI_VAL_INTEGER_BITS_8",
			"16" => "CLI_VAL_INTEGER_BITS_16",
			"32" => "CLI_VAL_INTEGER_BITS_32",
			"64" => "CLI_VAL_INTEGER_BITS_64",
		],
	],
	[
		"name" => "val_integer_sign",
		"type" => "enum cli_val_integer_sign",
		"values" => [
			"unsigned" => "CLI_VAL_INTEGER_SIGN_UNSIGNED",
			"twos-complement" => "CLI_VAL_INTEGER_SIGN_TWOS_COMPLEMENT",
		],
	],
	[
		"name" => "val_ieee754_precision",
		"type" => "enum cli_val_ieee754_precision",
		"values" => [
			"single" => "CLI_VAL_IEEE754_PRECISION_SINGLE",
			"double" => "CLI_VAL_IEEE754_PRECISION_DOUBLE",
			"extended" => "CLI_VAL_IEEE754_PRECISION_EXTENDED",
		],
	],
	[
		"name" => "val_text_encoding",
		"type" => "enum cli_val_text_encoding",
		"values" => [
			"ascii" => "CLI_VAL_TEXT_ENCODING_ASCII",
		],
	],
	[
		"name" => "val_x86_mode",
		"type" => "enum cli_val_x86_mode",
		"values" => [
			"16" => "CLI_VAL_X86_MODE_16",
			"32" => "CLI_VAL_X86_MODE_32",
			"64" => "CLI_VAL_X86_MODE_64",
		],
	],
	[
		"name" => "val_x86_syntax",
		"type" => "enum cli_val_x86_syntax",
		"values" => [
			"intel" => "CLI_VAL_X86_SYNTAX_INTEL",
			"att" => "CLI_VAL_X86_SYNTAX_ATT",
		],
	],
	[
		"name" => "val_arm_mode",
		"type" => "enum cli_val_arm_mode",
		"values" => [
			"a32" => "CLI_VAL_ARM_MODE_A32",
			"t32" => "CLI_VAL_ARM_MODE_T32",
			"a64" => "CLI_VAL_ARM_MODE_A64",
		],
	],
	[
		"name" => "val_arm_endianness",
		"type" => "enum cli_val_arm_endianness",
		"values" => [
			"little" => "CLI_VAL_ARM_ENDIANNESS_LITTLE",
			"big" => "CLI_VAL_ARM_ENDIANNESS_BIG",
		],
	],
	[
		"name" => "val_sparc_mode",
		"type" => "enum cli_val_sparc_mode",
		"values" => [
			"32" => "CLI_VAL_SPARC_MODE_32",
			"64" => "CLI_VAL_SPARC_MODE_64",
			"v9" => "CLI_VAL_SPARC_MODE_V9",
		],
	],
	[
		"name" => "val_sparc_endianness",
		"type" => "enum cli_val_sparc_endianness",
		"values" => [
			"little" => "CLI_VAL_SPARC_ENDIANNESS_LITTLE",
			"big" => "CLI_VAL_SPARC_ENDIANNESS_BIG",
		],
	],
	[
		"name" => "val_powerpc_mode",
		"type" => "enum cli_val_powerpc_mode",
		"values" => [
			"32" => "CLI_VAL_POWERPC_MODE_32",
			"64" => "CLI_VAL_POWERPC_MODE_64",
			"qpx" => "CLI_VAL_POWERPC_MODE_QPX",
		],
	],
	[
		"name" => "val_powerpc_endianness",
		"type" => "enum cli_val_powerpc_endianness",
		"values" => [
			"little" => "CLI_VAL_POWERPC_ENDIANNESS_LITTLE",
			"big" => "CLI_VAL_POWERPC_ENDIANNESS_BIG",
		],
	],
	[
		"name" => "val_mips_mode",
		"type" => "enum cli_val_mips_mode",
		"values" => [
			"micro" => "CLI_VAL_MIPS_MODE_MICRO",
			"3" => "CLI_VAL_MIPS_MODE_3",
			"32r6" => "CLI_VAL_MIPS_MODE_32R6",
			"32" => "CLI_VAL_MIPS_MODE_32",
			"64" => "CLI_VAL_MIPS_MODE_64",
		],
	],
	[
		"name" => "val_mips_endianness",
		"type" => "enum cli_val_mips_endianness",
		"values" => [
			"little" => "CLI_VAL_MIPS_ENDIANNESS_LITTLE",
			"big" => "CLI_VAL_MIPS_ENDIANNESS_BIG",
		],
	],
	[
		"name" => "cmd_execute_format",
		"type" => "enum cli_cmd_execute_format",
		"values" => [
			"assembly" => "CLI_CMD_EXECUTE_FORMAT_ASSEMBLY",
			"bytecode" => "CLI_CMD_EXECUTE_FORMAT_BYTECODE",
		],
	],
	[
		"name" => "assembler_architecture",
		"type" => "enum cli_assembler_architecture",
		"values" => [
			"x86" => "CLI_ASSEMBLER_ARCHITECTURE_X86",
			"arm" => "CLI_ASSEMBLER_ARCHITECTURE_ARM",
			"sparc" => "CLI_ASSEMBLER_ARCHITECTURE_SPARC",
			"powerpc" => "CLI_ASSEMBLER_ARCHITECTURE_POWERPC",
			"mips" => "CLI_ASSEMBLER_ARCHITECTURE_MIPS",
		],
	],
	[
		"name" => "assembler_endianness",
		"type" => "enum cli_assembler_endianness",
		"values" => [
			"little" => "CLI_ASSEMBLER_ENDIANNESS_LITTLE",
			"big" => "CLI_ASSEMBLER_ENDIANNESS_BIG",
		],
	],
	[
		"name" => "assembler_x86_mode",
		"type" => "enum cli_assembler_x86_mode",
		"values" => [
			"16" => "CLI_ASSEMBLER_X86_MODE_16",
			"32" => "CLI_ASSEMBLER_X86_MODE_32",
			"64" => "CLI_ASSEMBLER_X86_MODE_64",
		],
	],
	[
		"name" => "assembler_x86_syntax",
		"type" => "enum cli_assembler_x86_syntax",
		"values" => [
			"intel" => "CLI_ASSEMBLER_X86_SYNTAX_INTEL",
			"att" => "CLI_ASSEMBLER_X86_SYNTAX_ATT",
		],
	],
	[
		"name" => "assembler_arm_mode",
		"type" => "enum cli_assembler_arm_mode",
		"values" => [
			"a32" => "CLI_ASSEMBLER_ARM_MODE_A32",
			"t32" => "CLI_ASSEMBLER_ARM_MODE_T32",
			"a64" => "CLI_ASSEMBLER_ARM_MODE_A64",
		],
	],
	[
		"name" => "assembler_sparc_mode",
		"type" => "enum cli_assembler_sparc_mode",
		"values" => [
			"32" => "CLI_ASSEMBLER_SPARC_MODE_32",
			"64" => "CLI_ASSEMBLER_SPARC_MODE_64",
			"v9" => "CLI_ASSEMBLER_SPARC_MODE_V9",
		],
	],
	[
		"name" => "assembler_powerpc_mode",
		"type" => "enum cli_assembler_powerpc_mode",
		"values" => [
			"32" => "CLI_ASSEMBLER_POWERPC_MODE_32",
			"64" => "CLI_ASSEMBLER_POWERPC_MODE_64",
			"qpx" => "CLI_ASSEMBLER_POWERPC_MODE_QPX",
		],
	],
	[
		"name" => "assembler_mips_mode",
		"type" => "enum cli_assembler_mips_mode",
		"values" => [
			"micro" => "CLI_ASSEMBLER_MIPS_MODE_MICRO",
			"3" => "CLI_ASSEMBLER_MIPS_MODE_3",
			"32r6" => "CLI_ASSEMBLER_MIPS_MODE_32R6",
			"32" => "CLI_ASSEMBLER_MIPS_MODE_32",
			"64" => "CLI_ASSEMBLER_MIPS_MODE_64",
		],
	],
	[
		"name" => "proctal_region",
		"type" => "int",
		"values" => [
			"stack" => "PROCTAL_REGION_STACK",
			"heap" => "PROCTAL_REGION_HEAP",
			"program-code" => "PROCTAL_REGION_PROGRAM_CODE",
		],
	],
];

?>
#include <string.h>

#include "api/include/proctal.h"
#include "cli/parser.h"
#include "magic/magic.h"

<?php foreach ($parsers as $parser): ?>
	int cli_parse_<?= $parser["name"] ?>(const char *s, <?= $parser["type"] ?>* val)
	{
		static char *options[] = {
			<?php foreach ($parser["values"] as $text => $_): ?>
				"<?= addslashes($text) ?>",
			<?php endforeach ?>
		};

		static <?= $parser["type"] ?> values[] = {
			<?php foreach ($parser["values"] as $value): ?>
				<?= $value ?>,
			<?php endforeach ?>
		};

		for (size_t i = 0; i < ARRAY_SIZE(options); i++) {
			if (strcmp(options[i], s) == 0) {
				*val = values[i];
				return 1;
			}
		}

		return 0;
	}
<?php endforeach ?>
