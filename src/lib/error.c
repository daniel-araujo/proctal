#include <stdlib.h>
#include <proctal.h>

static const char *a[] = {
	[0] = NULL,
	[PROCTAL_ERROR_PERMISSION_DENIED] = "Permission denied.",
	[PROCTAL_ERROR_WRITE_FAILURE] = "Failed to write everything out.",
	[PROCTAL_ERROR_READ_FAILURE] = "Failed to read everything in.",
};

const char *proctal_error_msg(proctal p)
{
	return a[proctal_error(p)];
}
