/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@fastmail.fm>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#pragma once

#include <inttypes.h>

struct config {
	char isns_server[64];
	uint16_t isns_port;
	int log_level;
	char configfs_iscsi_path[256];
};

extern struct config config;

void pidfile_create(void);

void pidfile_remove(void);

int conffile_read(void);
