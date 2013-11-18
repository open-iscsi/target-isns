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

#include "util.h"
#include "log.h"
#include <ccan/str/str.h>
#include <ctype.h>
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#define PIDFILE		"/run/target-isns.pid"
#define CONFFILE	"/etc/target-isns.conf"

void pidfile_create(void)
{
	FILE *file;

	pidfile_remove();
	if ((file = fopen(PIDFILE, "w")) != NULL) {
		fprintf(file, "%d\n", getpid());
		fclose(file);
	}
}

void pidfile_remove(void)
{

	unlink(PIDFILE);
}

int conffile_read(void)
{
	FILE *file;
	char line[1024];

	memset(&config, sizeof(config), 0);
	config.log_level = LOG_INFO;

	if ((file = fopen(CONFFILE, "r")) == NULL) {
		log_print(LOG_ERR, "Could not read " CONFFILE);
		return -1;
	}
	while (fgets(line, sizeof(line), file)) {
		char *p, *key, *value;
		size_t len;

		p = line;
		while (isblank(*p))
			p++;

		if (*p == '#' || *p == '\0' || *p == '\n')
			continue;

		value = strchr(p, '=');
		if (*p == '=' || value == NULL) {
			log_print(LOG_WARNING, "Cannot parse '%s' in " CONFFILE, line);
			continue;
		}
		key = p;
		*value = '\0';
		value++;

		/* Remove blank chars at the end of the key */
		len = strlen(key);
		for (size_t i = 0; i < len; i++) {
			if (isblank(key[i])) {
				key[i] = '\0';
				break;
			}
		}

		/* Remove blank chars before and after the value */
		while (isblank(*value))
			value++;
		len = strlen(value);
		for (size_t i = 0; i < len; i++) {
			if (isblank(value[i]) || value[i] == '\n') {
				value[i] = '\0';
				break;
			}
		}

		if (streq(key, "isns_server")) {
			const size_t sz = sizeof(config.isns_server);
			strncpy(config.isns_server, value, sz);
			config.isns_server[sz - 1] = '\0';
		} else if (streq(key, "log_level")) {
			if (streq(value, "info"))
				config.log_level = LOG_INFO;
			else if (streq(value, "debug"))
				config.log_level = LOG_DEBUG;
		}
	}
	fclose(file);

	return 0;
}
