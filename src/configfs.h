/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef __CONFIGFS_H__
#define __CONFIGFS_H__

#include <arpa/inet.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <sys/inotify.h>
#include <ccan/list/list.h>

struct target {
	struct list_node list;
	char name[224];
	struct list_head tpgs;
	bool updated;
	int watch_fd;
};

struct tpg {
	struct list_node list;
	uint16_t tag;
	bool enabled;
	struct list_head portals;
	bool updated;
	int watch_fd;
	int np_watch_fd;
};

struct portal {
	struct list_node list;
	int af;
	char ip_addr[INET6_ADDRSTRLEN];
	uint16_t port;
	bool updated;
};

#define ALL_TARGETS ((struct target*) 1)

bool configfs_iscsi_path_exists(void);

int configfs_init(void);

void configfs_cleanup(void);

void configfs_show(void);

void configfs_handle_events(void);

struct target *target_find(const char *target_name);

#endif
