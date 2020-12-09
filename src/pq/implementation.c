#include "pq/implementation.h"
#include "config.h"

#ifdef PROCTAL_PLATFORM_LINUX

	#include "pq/posix/implementation.c"

#elif defined PROCTAL_PLATFORM_WINDOWS

	#include "pq/windows-posix/implementation.c"

#else

	#include "pq/unimplemented.c"

#endif
