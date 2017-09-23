#ifndef MAGIC_MAGIC_H
#define MAGIC_MAGIC_H

/*
 * This file provides functions and macros that perform C magic tricks.
 */

/*
 * Dereferences a pointer to a specific type.
 */
#define DEREF(T, P) (*(T *) (P))

/*
 * Figures out the size of an array statically.
 */
#define ARRAY_SIZE(A) (sizeof(A) / sizeof(A[0]))

/*
 * Compares two integer values.
 * 
 * Results in 0 if both are equal, 1 if X is greater than Y and -1 if X is
 * less than Y.
 */
#define COMPARE_INT(X, Y) (((X) > (Y)) - ((X) < (Y)))

/*
 * Like COMPARE_INT but works on floating point numbers.
 */
#define COMPARE_FLOAT(X, Y) ((X) == (Y) ? 0 : ((X) > (Y) ? 1 : -1))

#endif /* MAGIC_MAGIC_H */
