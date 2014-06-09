/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
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
		if (*p == '=' || !value) {
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
