/*
 * (C) Copyright 2007-2014
 * Rusty Russell <rusty@rustcorp.com.au>
 *
 * SPDX-License-Identifier:     CC0-1.0
 */

#ifndef CCAN_ARRAY_SIZE_H
#define CCAN_ARRAY_SIZE_H

/**
 * ARRAY_SIZE - get the number of elements in a visible array
 * @arr: the array whose size you want.
 *
 * This does not work on pointers, or arrays declared as [], or
 * function parameters.  With correct compiler support, such usage
 * will cause a build error.
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + _array_size_chk(arr))

/* Two gcc extensions.
 * &a[0] degrades to a pointer: a different type from an array */
#define _array_size_chk(arr)						\
	!__builtin_types_compatible_p(__typeof__(arr), __typeof__(&(arr)[0]))

#endif /* CCAN_ARRAY_SIZE_H */
