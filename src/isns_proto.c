/*
 * (C) Copyright 2014
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#include <inttypes.h>
#include <stdlib.h>
#include <ccan/array_size/array_size.h>

#include "isns_proto.h"


/* Array of iSNSP functions abbreviations */
#define X(MSG, ABBR, FUNCTION) {.function = FUNCTION, .abbr = ABBR},
static const struct {
	uint16_t function;
	char abbr[16];
} isns_abbrs[] = { ISNS_MESSAGE_TABLE };
#undef X


const char *isns_function_get_abbr(uint16_t function)
{
	for (size_t i = 0; i < ARRAY_SIZE(isns_abbrs); i++) {
		if (isns_abbrs[i].function == function)
			return isns_abbrs[i].abbr;
	}

	return NULL;
}
