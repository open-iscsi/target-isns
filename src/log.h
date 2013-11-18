/*
 * This file is part of target-isns.
 *
 * Copyright (C) 2013 Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * target-isns is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * target-isns is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with target-isns; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef __LOG_H__
#define __LOG_H__

#include <stdbool.h>
#include <syslog.h>


void log_init(const char *progname, bool daemon, int priority);

void log_close(void);

void log_print(int priority, const char *format, ...) __attribute__((format(printf, 2, 3)));

#endif
