/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

/*
 * This file defines functions and data structures to get an in-memory
 * representation of the iSCSI configuration by browsing and watching
 * the config file system.
 *
 * There may be one or more targets. Each target can contain one or
 * more target portal groups (TPG) and each TPG can contain one or
 * more portals. These elements are monitored with inotify. Because
 * inotify monitoring of directories is not recursive, inotify watches
 * must be created in directories whose content is of interest (marked
 * 'W' below).
 *
 *   configfs hierarchy                     target-isns data structure
 *
 *   /sys/kernel/config/target/iscsi/   W   targets
 *   +-- $IQN 1                         W   +-- target 1
 *   |   +-- tpgt_1                     W   |   +-- tpg 1
 *   |   |   +-- np                     W   |   |   |
 *   |   |   |   +-- $IP:$PORT              |   |   +-- portal 1
 *   |   |   |   +-- $IP:$PORT              |   |   +-- portal 2
 *   |   |   +-- param                      |   |
 *   |   |       +-- TargetAlias            |   |
 *   |   +-- tpgt_N                     W   |   +-- tpg N
 *   +-- $IQN N                         W   +-- target N
 */

#include "configfs.h"

#include <ccan/list/list.h>
#include <ccan/str/str.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

#include "isns.h"
#include "log.h"

#define CONFIGFS_ISCSI_PATH	"/sys/kernel/config/target/iscsi"
#define INOTIFY_MASK	       	(IN_CREATE | IN_DELETE | IN_MODIFY)
#define INOTIFY_BUF_LEN		(16 * (sizeof(struct inotify_event) + NAME_MAX + 1))


LIST_HEAD(targets);
static int inotify_fd = -1;

struct tpg {
	struct list_node list;
	uint32_t id;
	bool enabled;
	struct list_head portals;
	bool updated;
	int watch_fd;
};

struct portal {
	struct list_node list;
	int domain;
	unsigned char ip_addr[sizeof(struct in6_addr)];
	int port;
	bool updated;
};


bool configfs_iscsi_path_exists(void)
{
	DIR *dir = opendir(CONFIGFS_ISCSI_PATH);

	if (dir) {
		closedir(dir);
		return true;
	}
	return false;
}

static struct target *configfs_target_init(const char *name)
{
	struct target *tgt;
	char path[512];

	if ((tgt = malloc(sizeof(struct target))) == NULL)
		return NULL;

	snprintf(path, sizeof(path), CONFIGFS_ISCSI_PATH "/%s", name);
	strcpy(tgt->name, name);
	tgt->updated = false;
	tgt->watch_fd = inotify_add_watch(inotify_fd, path, INOTIFY_MASK);
	list_head_init(&tgt->tpgs);
	list_add_tail(&targets, &tgt->list);

	return tgt;
}

static bool configfs_tpg_enabled(struct target *tgt, uint32_t tpg_id)
{
	int fd;
	ssize_t nr;
	char buf[8], path[512];
	bool enabled = false;

	snprintf(path, sizeof(path),
		 CONFIGFS_ISCSI_PATH "/%s/tpgt_%" PRIu32 "/enable",
		 tgt->name, tpg_id);
	if ((fd = open(path, O_RDONLY)) == -1)
		return false;
	if ((nr = read(fd, buf, sizeof(buf))) != -1) {
		enabled = buf[0] == '1';
	}
	close(fd);

	return enabled;
}

static struct tpg *configfs_tpg_init(struct target *tgt, uint32_t tpg_id)
{
	struct tpg *tpg = malloc(sizeof(struct tpg));
	char path[512];

	snprintf(path, sizeof(path),
		 CONFIGFS_ISCSI_PATH "/%s/tpgt_%" PRIu32,
		 tgt->name, tpg_id);
	tpg->id = tpg_id;
	tpg->enabled = configfs_tpg_enabled(tgt, tpg_id);
	tpg->updated = false;
	tpg->watch_fd = inotify_add_watch(inotify_fd, path, INOTIFY_MASK);
	list_head_init(&tpg->portals);
	list_add(&tgt->tpgs, &tpg->list);

	return tpg;
}

static int get_portal(const char *str, int *domain, char *ip_addr, int *port)
{
	char *p = strrchr(str, ':');

	if (p == NULL)
		return -EINVAL;

	if (sscanf(p, ":%d", port) != 1)
		return -EINVAL;

	*p = '\0';
	*domain = strchr(str, ':') ? AF_INET6 : AF_INET;
	if (inet_pton(*domain, str, ip_addr) != 1)
		return -EINVAL;

	return 0;
}

static struct portal *configfs_portal_init(struct tpg *tpg, int domain,
					   const char *ip_addr, int port)
{
	struct portal *portal = malloc(sizeof(struct portal));

	portal->domain = domain;
	memcpy(portal->ip_addr, ip_addr, sizeof(struct in6_addr));
	portal->port = port;
	portal->updated = false;
	list_add(&tpg->portals, &portal->list);

	return portal;
}

static int configfs_tpg_update(struct target *tgt, struct tpg *tpg)
{
	DIR *np_dir;
	struct dirent *dirent;
	struct portal *portal, *portal_next;
	char np_path[512];

	snprintf(np_path, sizeof(np_path),
		 CONFIGFS_ISCSI_PATH "/%s/tpgt_%" PRIu32 "/np",
		 tgt->name, tpg->id);
	np_dir = opendir(np_path);
	if (np_dir == NULL)
		return -ENOENT;

	list_for_each(&tpg->portals, portal, list) {
		portal->updated = false;
	}

	while ((dirent = readdir(np_dir))) {
		if (streq(dirent->d_name, ".") || streq(dirent->d_name, ".."))
			continue;

		int domain;
		char ip_addr[sizeof(struct in6_addr)];
		int port;
		if (get_portal(dirent->d_name, &domain, ip_addr, &port) != 0)
			continue;

		struct portal *p;
		portal = NULL;
		list_for_each(&tpg->portals, p, list) {
			if (memcmp(p->ip_addr, ip_addr, sizeof(ip_addr)) == 0 &&
			    p->port == port)
				portal = p;
		}

		if (!portal)
			portal = configfs_portal_init(tpg, domain, ip_addr, port);
		portal->updated = true;
	}
	closedir(np_dir);

	list_for_each_safe(&tpg->portals, portal, portal_next, list) {
		if (portal->updated)
			continue;

		list_del(&portal->list);
		free(portal);
	}
	tpg->updated = true;

	return 0;
}

static int configfs_target_update(struct target *tgt)
{
	DIR *tgt_dir;
	struct dirent *dirent;
	struct tpg *tpg, *tpg_next;
	uint32_t tpg_id;
	char tgt_path[512];

	snprintf(tgt_path, sizeof(tgt_path), CONFIGFS_ISCSI_PATH "/%s", tgt->name);
	tgt_dir = opendir(tgt_path);
	if (tgt_dir == NULL)
		return -ENOENT;

	list_for_each(&tgt->tpgs, tpg, list) {
		tpg->updated = false;
	}

	while ((dirent = readdir(tgt_dir))) {
		if (!strstarts(dirent->d_name, "tpgt_"))
			continue;

		sscanf(dirent->d_name, "tpgt_%" PRIu32, &tpg_id);

		struct tpg *p;
		tpg = NULL;
		list_for_each(&tgt->tpgs, p, list) {
			if (p->id == tpg_id)
				tpg = p;
		}

		if (!tpg)
			tpg = configfs_tpg_init(tgt, tpg_id);
		configfs_tpg_update(tgt, tpg);
	}
	closedir(tgt_dir);

	list_for_each_safe(&tgt->tpgs, tpg, tpg_next, list) {
		if (tpg->updated)
			continue;

		list_del(&tpg->list);
		free(tpg);
	}
	tgt->updated = true;

	isns_target_register(tgt->name);

	return 0;
}

int configfs_init(void)
{
	DIR *iscsi_dir;
	struct dirent *dirent;
	struct target *tgt, *tgt_next;

	if ((inotify_fd = inotify_init()) == -1)
		return -1;

	if (inotify_add_watch(inotify_fd, CONFIGFS_ISCSI_PATH, INOTIFY_MASK) == -1)
		goto out;

	iscsi_dir = opendir(CONFIGFS_ISCSI_PATH);
	if (iscsi_dir == NULL)
		goto out;

	list_for_each(&targets, tgt, list) {
		tgt->updated = false;
	}

	while ((dirent = readdir(iscsi_dir))) {
		if (!strstarts(dirent->d_name, "iqn."))
			continue;

		tgt = target_find(dirent->d_name);
		if (!tgt)
			tgt = configfs_target_init(dirent->d_name);
		configfs_target_update(tgt);
	}
	closedir(iscsi_dir);

	list_for_each_safe(&targets, tgt, tgt_next, list) {
		if (tgt->updated)
			continue;

		list_del(&tgt->list);
		inotify_rm_watch(inotify_fd, tgt->watch_fd);
		free(tgt);
	}

	return inotify_fd;

out:
	close(inotify_fd);
	inotify_fd = -1;

	return -1;
}

void configfs_cleanup(void)
{
	struct target *tgt, *tgt_next;
	struct tpg *tpg, *tpg_next;
	struct portal *portal, *portal_next;

	list_for_each_safe(&targets, tgt, tgt_next, list) {
		list_for_each_safe(&tgt->tpgs, tpg, tpg_next, list) {
			list_for_each_safe(&tpg->portals, portal, portal_next, list) {
				list_del(&portal->list);
				free(portal);
			}
			list_del(&tpg->list);
			inotify_rm_watch(inotify_fd, tpg->watch_fd);
			free(tpg);
		}
		isns_target_deregister(tgt->name);
		list_del(&tgt->list);
		inotify_rm_watch(inotify_fd, tgt->watch_fd);
		free(tgt);
	}
	close(inotify_fd);
}

void configfs_show(void)
{
	struct target *tgt;
	struct tpg *tpg;
	struct portal *portal;
	char str[INET6_ADDRSTRLEN];

	list_for_each(&targets, tgt, list) {
		log_print(LOG_DEBUG, "target: name = %s", tgt->name);
		list_for_each(&tgt->tpgs, tpg, list) {
			log_print(LOG_DEBUG, "  tpg: id = %" PRIu32 ", enabled = %d",
				  tpg->id, tpg->enabled);
			list_for_each(&tpg->portals, portal, list) {
				inet_ntop(portal->domain, portal->ip_addr, str, INET6_ADDRSTRLEN);
				log_print(LOG_DEBUG, "    portal: domain = IP%s, ip_addr = %s, port = %d",
					  portal->domain == AF_INET ? "v4" : "v6", str, portal->port);
			}
		}
	}
}

static void configfs_handle_target(const struct inotify_event *event)
{
	struct target *tgt = target_find(event->name);

	if ((event->mask & IN_CREATE) && tgt == NULL) {
		tgt = configfs_target_init(event->name);
		configfs_target_update(tgt);
	} else if ((event->mask & IN_DELETE) && tgt) {
		isns_target_deregister(tgt->name);
		list_del(&tgt->list);
		inotify_rm_watch(inotify_fd, tgt->watch_fd);
		free(tgt);
	} else if ((event->mask & IN_MODIFY) && tgt) {
		configfs_target_update(tgt);
	}
}

static void configfs_handle_tpg(const struct inotify_event *event)
{
	struct target *tgt;
	struct tpg *tpg = NULL, *t;
	uint32_t tpg_id;

	if (sscanf(event->name, "tpgt_%" PRIu32, &tpg_id) != 1)
		return;

	list_for_each(&targets, tgt, list) {
		list_for_each(&tgt->tpgs, t, list) {
			if (t->id == tpg_id) {
				tpg = t;
				goto found;
			}
		}
	}
	if (tpg == NULL)
		return;
found:
	if ((event->mask & IN_CREATE) && tpg == NULL) {
		tpg = configfs_tpg_init(tgt, tpg_id);
		configfs_tpg_update(tgt, tpg);
	} else if ((event->mask & IN_DELETE) && tpg) {
		list_del(&tpg->list);
		inotify_rm_watch(inotify_fd, tpg->watch_fd);
		free(tpg);
	} else if ((event->mask & IN_MODIFY) && tpg) {
		configfs_tpg_update(tgt, tpg);
	}
}

static void configfs_handle_portal(const struct inotify_event *event __attribute__ ((unused)))
{
	return;
}

void configfs_handle_events(void)
{
	ssize_t nr;
	char buf[INOTIFY_BUF_LEN];
	struct inotify_event *event;
	char *p;

	nr = read(inotify_fd, buf, INOTIFY_BUF_LEN);
	for (p = buf; p < buf + nr; ) {
		event = (struct inotify_event*) p;
		p += sizeof(struct inotify_event) + event->len;
		if (strstarts(event->name, "iqn."))
			configfs_handle_target(event);
		else if (strstarts(event->name, "tpgt_"))
			configfs_handle_tpg(event);
		else if (streq(event->name, "np"))
			configfs_handle_portal(event);
	}
}

struct target *target_find(const char *target_name)
{
	struct target *tgt;

	list_for_each(&targets, tgt, list) {
		if (streq(tgt->name, target_name))
			return tgt;
	}
	return NULL;
}
