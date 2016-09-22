/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@fastmail.fm>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#pragma once

#include <stdbool.h>
#include <syslog.h>


void log_init(const char *progname, bool daemon, int priority);

void log_close(void);

void log_print(int priority, const char *format, ...) __attribute__((format(printf, 2, 3)));
