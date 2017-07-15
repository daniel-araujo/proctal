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
		],
	],
	[
		"name" => "val_integer_size",
		"type" => "enum cli_val_integer_size",
		"values" => [
			"8" => "CLI_VAL_INTEGER_SIZE_8",
			"16" => "CLI_VAL_INTEGER_SIZE_16",
			"32" => "CLI_VAL_INTEGER_SIZE_32",
			"64" => "CLI_VAL_INTEGER_SIZE_64",
		],
	],
	[
		"name" => "val_integer_sign",
		"type" => "enum cli_val_integer_sign",
		"values" => [
			"unsigned" => "CLI_VAL_INTEGER_SIGN_UNSIGNED",
			"2scmpl" => "CLI_VAL_INTEGER_SIGN_2SCMPL",
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
		"name" => "val_text_charset",
		"type" => "enum cli_val_text_charset",
		"values" => [
			"ascii" => "CLI_VAL_TEXT_CHARSET_ASCII",
		],
	],
	[
		"name" => "val_instruction_arch",
		"type" => "enum cli_val_instruction_arch",
		"values" => [
			"x86" => "CLI_VAL_INSTRUCTION_ARCH_X86",
			"x86-64" => "CLI_VAL_INSTRUCTION_ARCH_X86_64",
			"arm" => "CLI_VAL_INSTRUCTION_ARCH_ARM",
			"aarch64" => "CLI_VAL_INSTRUCTION_ARCH_AARCH64",
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
		"name" => "assembler_arch",
		"type" => "enum cli_assembler_arch",
		"values" => [
			"x86" => "CLI_ASSEMBLER_ARCH_X86",
			"x86-64" => "CLI_ASSEMBLER_ARCH_X86_64",
			"arm" => "CLI_ASSEMBLER_ARCH_ARM",
			"aarch64" => "CLI_ASSEMBLER_ARCH_AARCH64",
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
];

?>
#include <string.h>

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
