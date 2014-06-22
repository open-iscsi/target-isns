/*
 * (C) Copyright 2007-2014
 * Rusty Russell <rusty@rustcorp.com.au>
 *
 * SPDX-License-Identifier:     CC0-1.0
 */

#pragma once

#include <ccan/build_assert/build_assert.h>

/**
 * ARRAY_SIZE - get the number of elements in a visible array
 * @arr: the array whose size you want.
 *
 * This does not work on pointers, or arrays declared as [], or
 * function parameters.  With correct compiler support, such usage
 * will cause a build error (see build_assert).
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]) + _array_size_chk(arr))

/* Two gcc extensions.
 * &a[0] degrades to a pointer: a different type from an array */
#define _array_size_chk(arr)						\
	BUILD_ASSERT_OR_ZERO(!__builtin_types_compatible_p(__typeof__(arr),	\
							   __typeof__(&(arr)[0])))
