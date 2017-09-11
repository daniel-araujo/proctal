<?php

/*
 * This script generates the error messages.
 *
 * Always make sure that every error code has a message. In the future this
 * script could be extended to verify that.
 */

$messages = [
	"PROCTAL_ERROR_OUT_OF_MEMORY" => "Out of memory.",
	"PROCTAL_ERROR_PERMISSION_DENIED" => "Permission denied.",
	"PROCTAL_ERROR_WRITE_FAILURE" => "Failed to write everything out.",
	"PROCTAL_ERROR_READ_FAILURE" => "Failed to read everything in.",
	"PROCTAL_ERROR_UNKNOWN" => "Unknown failure.",
	"PROCTAL_ERROR_UNIMPLEMENTED" => "Not implemented.",
	"PROCTAL_ERROR_UNSUPPORTED" => "Not supported.",
	"PROCTAL_ERROR_UNSUPPORTED_WATCH_READ" => "Watching only for reads is not supported yet. You can watch for both reads and writes in the mean time.",
	"PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_EXECUTE" => "Watching for reads and instruction executions at once is not supported.",
	"PROCTAL_ERROR_UNSUPPORTED_WATCH_WRITE_EXECUTE" => "Watching for writes and instruction executions at once is not supported.",
	"PROCTAL_ERROR_UNSUPPORTED_WATCH_READ_WRITE_EXECUTE" => "Watching for reads, writes and instruction executions at once is not supported.",
	"PROCTAL_ERROR_PROGRAM_NOT_FOUND" => "Program not found.",
	"PROCTAL_ERROR_PROGRAM_NOT_SET" => "Program was not set.",
	"PROCTAL_ERROR_INJECTION_LOCATION_NOT_FOUND" => "Could not find a suitable address in memory to inject code in.",
	"PROCTAL_ERROR_PROGRAM_SEGFAULT" => "Program hit segmentation fault.",
	"PROCTAL_ERROR_PROGRAM_EXITED" => "Program has exited.",
	"PROCTAL_ERROR_PROGRAM_STOPPED" => "Program has stopped.",
	"PROCTAL_ERROR_PROGRAM_UNTAMEABLE" => "Program is in a state that cannot be dealt with.",
	"PROCTAL_ERROR_PROGRAM_TRAPPED" => "Program got trapped.",
	"PROCTAL_ERROR_INTERRUPT" => "An interrupt occurred.",
	"PROCTAL_ERROR_PROGRAM_INTERRUPT" => "Program got interrupt.",
];

function format_message($code, $message) {
	return "$code $message";
}

?>
#include "api/proctal.h"

static const char *messages[] = {
	[0] = NULL,
	<?php foreach ($messages as $code => $message): ?>
		[<?= $code ?>] = "<?= addslashes(format_message($code, $message)) ?>",
	<?php endforeach ?>
};

const char *proctal_error_message(struct proctal *p)
{
	return messages[proctal_error(p)];
}
