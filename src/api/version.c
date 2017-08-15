#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "api/proctal.h"
#include "api/implementation.h"

unsigned int proctal_version_major(void)
{
	return PROCTAL_VERSION_MAJOR;
}

unsigned int proctal_version_minor(void)
{
	return PROCTAL_VERSION_MINOR;
}

unsigned int proctal_version_patch(void)
{
	return PROCTAL_VERSION_PATCH;
}
