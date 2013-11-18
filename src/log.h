/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef __LOG_H__
#define __LOG_H__

#include <stdbool.h>
#include <syslog.h>


void log_init(const char *progname, bool daemon, int priority);

void log_close(void);

void log_print(int priority, const char *format, ...) __attribute__((format(printf, 2, 3)));

#endif
