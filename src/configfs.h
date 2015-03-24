/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#pragma once

#include <arpa/inet.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <sys/inotify.h>
#include <ccan/list/list.h>
#include "isns_proto.h"

struct target {
	struct list_node node;  /* Member of the global "targets" list */
	char name[ISCSI_NAME_SIZE];
	struct list_head tpgs;
	bool exists;
	bool registration_pending;
	int watch_fd;
};

struct tpg {
	struct list_node node;  /* Member of a target->tpg list */
	uint16_t tag;
	bool enabled;
	struct list_head portals;
	bool exists;
	int watch_fd;
	int np_watch_fd;
};

struct portal {
	struct list_node node;  /* Member of a tpg->portals list */
	int af;
	char ip_addr[INET6_ADDRSTRLEN];
	uint16_t port;
	bool exists;
};

#define ALL_TARGETS ((struct target*) 1)

bool configfs_iscsi_path_exists(void);

int configfs_inotify_init(void);

void configfs_inotify_cleanup(void);

void configfs_show(void);

void configfs_inotify_events_handle(void);

struct target *target_find(const char *target_name);
