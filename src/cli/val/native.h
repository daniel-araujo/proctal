#ifndef CLI_VAL_NATIVE_H
#define CLI_VAL_NATIVE_H

#include "magic/magic.h"

#define NATIVE_ADD(TYPE, V1, V2, VR) \
	(DEREF(TYPE, VR) = DEREF(TYPE, V1) + DEREF(TYPE, V2)), 1

#define NATIVE_SUB(TYPE, V1, V2, VR) \
	(DEREF(TYPE, VR) = DEREF(TYPE, V1) - DEREF(TYPE, V2)), 1

#define NATIVE_CMP(TYPE, V1, V2) \
	COMPARE(DEREF(TYPE, V1), DEREF(TYPE, V2))

#endif /* CLI_VAL_NATIVE_H */
