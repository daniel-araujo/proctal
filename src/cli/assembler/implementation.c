#include "cli/assembler/implementation.h"
#include "config.h"

#ifdef PROCTAL_HAS_CAPSTONE

	#include "cli/assembler/implementation/with-capstone.c"

#else

	#include "cli/assembler/implementation/without-capstone.c"

#endif

#ifdef PROCTAL_HAS_KEYSTONE

	#include "cli/assembler/implementation/with-keystone.c"

#else

	#include "cli/assembler/implementation/without-keystone.c"

#endif