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
			"instruction" => "CLI_VAL_TYPE_INSTRUCTION",
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
		"name" => "val_instruction_architecture",
		"type" => "enum cli_val_instruction_architecture",
		"values" => [
			"x86" => "CLI_VAL_INSTRUCTION_ARCHITECTURE_X86",
			"x86-64" => "CLI_VAL_INSTRUCTION_ARCHITECTURE_X86_64",
			"arm" => "CLI_VAL_INSTRUCTION_ARCHITECTURE_ARM",
			"aarch64" => "CLI_VAL_INSTRUCTION_ARCHITECTURE_AARCH64",
		],
	],
	[
		"name" => "val_instruction_syntax",
		"type" => "enum cli_val_instruction_syntax",
		"values" => [
			"intel" => "CLI_VAL_INSTRUCTION_SYNTAX_INTEL",
			"att" => "CLI_VAL_INSTRUCTION_SYNTAX_ATT",
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
			"x86-64" => "CLI_ASSEMBLER_ARCHITECTURE_X86_64",
			"arm" => "CLI_ASSEMBLER_ARCHITECTURE_ARM",
			"aarch64" => "CLI_ASSEMBLER_ARCHITECTURE_AARCH64",
		],
	],
	[
		"name" => "assembler_syntax",
		"type" => "enum cli_assembler_syntax",
		"values" => [
			"intel" => "CLI_ASSEMBLER_SYNTAX_INTEL",
			"att" => "CLI_ASSEMBLER_SYNTAX_ATT",
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
