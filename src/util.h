/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef __UTIL_H__
#define __UTIL_H__

struct {
	char isns_server[64];
	int log_level;
} config;

void pidfile_create(void);

void pidfile_remove(void);

int conffile_read(void);

#endif
