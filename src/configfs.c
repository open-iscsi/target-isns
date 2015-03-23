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
#define INOTIFY_MASK		(IN_CREATE | IN_DELETE | IN_MODIFY)
#define INOTIFY_BUF_LEN		(16 * (sizeof(struct inotify_event) + NAME_MAX + 1))


LIST_HEAD(targets);
LIST_HEAD(portals);
LIST_HEAD(tpg_portals);
static int inotify_fd = -1;


/* Associative entity between a TPG and a portal */
struct tpg_portal {
	struct list_node node;  /* Member of the "tpg_portals" list */
	struct tpg *tpg;
	struct portal *portal;
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

static struct target *target_find_by_watch(int watch_fd)
{
	struct target *tgt;

	list_for_each(&targets, tgt, node) {
		if (tgt->watch_fd == watch_fd)
			return tgt;
	}
	return NULL;
}

static struct tpg *tpg_find_by_tag(const struct target *tgt, uint16_t tpg_tag)
{
	struct tpg *tpg;

	list_for_each(&tgt->tpgs, tpg, node) {
		if (tpg->tag == tpg_tag)
			return tpg;
	}
	return NULL;
}

static struct tpg *tpg_find_by_watch(const struct target *tgt, int watch_fd)
{
	struct tpg *tpg;

	list_for_each(&tgt->tpgs, tpg, node) {
		if (tpg->watch_fd == watch_fd ||
		    tpg->np_watch_fd == watch_fd)
			return tpg;
	}
	return NULL;
}

static struct target *configfs_target_init(const char *name)
{
	struct target *tgt;
	char path[512];

	if ((tgt = malloc(sizeof(struct target))) == NULL)
		return NULL;

	snprintf(path, sizeof(path), CONFIGFS_ISCSI_PATH "/%s", name);
	strncpy(tgt->name, name, ISCSI_NAME_SIZE);
	tgt->name[ISCSI_NAME_SIZE - 1] = '\0';
	tgt->exists = false;
	tgt->registration_pending = false;
	tgt->watch_fd = inotify_add_watch(inotify_fd, path, INOTIFY_MASK);
	list_head_init(&tgt->tpgs);
	list_add_tail(&targets, &tgt->node);

	return tgt;
}

static bool configfs_tpg_enabled(const struct target *tgt, uint16_t tpg_tag)
{
	int fd;
	ssize_t nr;
	char buf[8], path[512];
	bool enabled = false;

	snprintf(path, sizeof(path),
		 CONFIGFS_ISCSI_PATH "/%s/tpgt_%hu/enable",
		 tgt->name, tpg_tag);
	if ((fd = open(path, O_RDONLY)) == -1)
		return false;
	if ((nr = read(fd, buf, sizeof(buf))) != -1) {
		enabled = buf[0] == '1';
	}
	close(fd);

	return enabled;
}

static struct tpg *configfs_tpg_init(struct target *tgt, uint16_t tpg_tag)
{
	struct tpg *tpg = malloc(sizeof(struct tpg));
	char path[512];
	char np_path[512];

	snprintf(path, sizeof(path), CONFIGFS_ISCSI_PATH "/%s/tpgt_%hu",
		 tgt->name, tpg_tag);
	snprintf(np_path, sizeof(np_path), "%s/np", path);
	tpg->watch_fd = inotify_add_watch(inotify_fd, path, INOTIFY_MASK);
	tpg->np_watch_fd = inotify_add_watch(inotify_fd, np_path, INOTIFY_MASK);
	tpg->tag = tpg_tag;
	tpg->enabled = configfs_tpg_enabled(tgt, tpg_tag);
	tpg->exists = false;
	list_add(&tgt->tpgs, &tpg->node);

	return tpg;
}

static int get_portal(const char *str, int *af, char *ip_addr, uint16_t *port)
{
	uint8_t addr[sizeof(struct in6_addr)];
	char *p = strrchr(str, ':');

	if (!p)
		return -EINVAL;

	if (sscanf(p, ":%hu", port) != 1)
		return -EINVAL;

	*p = '\0';
	/* An IPv6 address in configfs is enclosed with []; remove them. */
	if (str[0] == '[') {
		*af = AF_INET6;
		str++;
		p = strchr(str, ']');
		*p = '\0';
	} else
		*af = AF_INET;

	if (inet_pton(*af, str, addr) != 1)
		return -EINVAL;

	strncpy(ip_addr, str, INET6_ADDRSTRLEN);

	return 0;
}

static struct portal *configfs_portal_init(int af, const char *ip_addr, uint16_t port)
{
	struct portal *portal = malloc(sizeof(struct portal));

	portal->af = af;
	strncpy(portal->ip_addr, ip_addr, INET6_ADDRSTRLEN);
	portal->ip_addr[INET6_ADDRSTRLEN - 1] = '\0';
	portal->port = port;
	portal->registered = false;
	list_add(&portals, &portal->node);

	return portal;
}

static struct tpg_portal *configfs_tpg_portal_init(struct tpg *tpg,
						   struct portal *portal)
{
	struct tpg_portal *tpg_portal = malloc(sizeof(struct tpg_portal));

	tpg_portal->tpg = tpg;
	tpg_portal->portal = portal;
	list_add(&tpg_portals, &tpg_portal->node);

	return tpg_portal;
}

static struct tpg_portal *configfs_tpg_portal_find(const struct tpg *tpg,
						   const struct portal *portal)
{
	struct tpg_portal *tpg_portal;

	list_for_each(&tpg_portals, tpg_portal, node) {
		if (tpg_portal->tpg == tpg && tpg_portal->portal == portal)
			return tpg_portal;
	}

	return NULL;
}

static int configfs_tpg_update(struct target *tgt, struct tpg *tpg)
{
	DIR *np_dir;
	struct dirent *dirent;
	char np_path[512];

	snprintf(np_path, sizeof(np_path),
		 CONFIGFS_ISCSI_PATH "/%s/tpgt_%hu/np",
		 tgt->name, tpg->tag);
	np_dir = opendir(np_path);
	if (!np_dir)
		return -ENOENT;

	tpg->enabled = configfs_tpg_enabled(tgt, tpg->tag);

	while ((dirent = readdir(np_dir))) {
		if (streq(dirent->d_name, ".") || streq(dirent->d_name, ".."))
			continue;

		int af;
		char ip_addr[INET6_ADDRSTRLEN];
		uint16_t port;
		if (get_portal(dirent->d_name, &af, ip_addr, &port) != 0)
			continue;

		struct portal *portal = portal_find(af, ip_addr, port);
		if (!portal)
			portal = configfs_portal_init(af, ip_addr, port);

		struct tpg_portal *tpg_portal = configfs_tpg_portal_find(tpg, portal);
		if (!tpg_portal)
			tpg_portal = configfs_tpg_portal_init(tpg, portal);
	}
	closedir(np_dir);

	return 0;
}

static int configfs_target_update(struct target *tgt)
{
	DIR *tgt_dir;
	struct dirent *dirent;
	struct tpg *tpg, *tpg_next;
	struct tpg_portal *tpg_portal, *tpg_portal_next;
	uint16_t tpg_tag;
	char tgt_path[512];

	snprintf(tgt_path, sizeof(tgt_path), CONFIGFS_ISCSI_PATH "/%s", tgt->name);
	tgt_dir = opendir(tgt_path);
	if (!tgt_dir)
		return -ENOENT;

	list_for_each(&tgt->tpgs, tpg, node) {
		tpg->exists = false;
	}

	while ((dirent = readdir(tgt_dir))) {
		if (!strstarts(dirent->d_name, "tpgt_"))
			continue;

		sscanf(dirent->d_name, "tpgt_%hu", &tpg_tag);
		tpg = tpg_find_by_tag(tgt, tpg_tag);

		if (!tpg)
			tpg = configfs_tpg_init(tgt, tpg_tag);
		configfs_tpg_update(tgt, tpg);
		tpg->exists = true;
	}
	closedir(tgt_dir);

	list_for_each_safe(&tgt->tpgs, tpg, tpg_next, node) {
		if (tpg->exists)
			continue;

		list_for_each_safe(&tpg_portals, tpg_portal, tpg_portal_next, node) {
			if (tpg_portal->tpg == tpg) {
				list_del(&tpg_portal->node);
				free(tpg_portal);
			}
		}

		list_del(&tpg->node);
		free(tpg);
	}
	tgt->exists = true;

	return 0;
}

int configfs_inotify_init(void)
{
	DIR *iscsi_dir;
	struct dirent *dirent;
	struct target *tgt, *tgt_next;

	if ((inotify_fd = inotify_init()) == -1)
		return -1;

	if (inotify_add_watch(inotify_fd, CONFIGFS_ISCSI_PATH, INOTIFY_MASK) == -1)
		goto out;

	iscsi_dir = opendir(CONFIGFS_ISCSI_PATH);
	if (!iscsi_dir)
		goto out;

	list_for_each(&targets, tgt, node) {
		tgt->exists = false;
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

	list_for_each_safe(&targets, tgt, tgt_next, node) {
		if (tgt->exists)
			continue;

		list_del(&tgt->node);
		inotify_rm_watch(inotify_fd, tgt->watch_fd);
		free(tgt);
	}

	return inotify_fd;

out:
	close(inotify_fd);
	inotify_fd = -1;

	return -1;
}

void configfs_inotify_cleanup(void)
{
	struct target *tgt, *tgt_next;
	struct tpg *tpg, *tpg_next;
	struct portal *portal, *portal_next;
	struct tpg_portal *tpg_portal, *tpg_portal_next;

	list_for_each_safe(&tpg_portals, tpg_portal, tpg_portal_next, node) {
		list_del(&tpg_portal->node);
		free(tpg_portal);
	}
	list_for_each_safe(&portals, portal, portal_next, node) {
		list_del(&portal->node);
		free(portal);
	}
	list_for_each_safe(&targets, tgt, tgt_next, node) {
		list_for_each_safe(&tgt->tpgs, tpg, tpg_next, node) {
			list_del(&tpg->node);
			inotify_rm_watch(inotify_fd, tpg->watch_fd);
			inotify_rm_watch(inotify_fd, tpg->np_watch_fd);
			free(tpg);
		}
		list_del(&tgt->node);
		inotify_rm_watch(inotify_fd, tgt->watch_fd);
		free(tgt);
	}
	close(inotify_fd);
}

void configfs_show(void)
{
	struct target *tgt;
	struct tpg *tpg;
	struct tpg_portal *tpg_portal;
	struct portal *portal;

	list_for_each(&targets, tgt, node) {
		log_print(LOG_DEBUG, "target: name = %s", tgt->name);
		list_for_each(&tgt->tpgs, tpg, node) {
			log_print(LOG_DEBUG, "  tpg: tag = %hu, enabled = %d",
				  tpg->tag, tpg->enabled);

			list_for_each(&tpg_portals, tpg_portal, node) {
				if (tpg_portal->tpg != tpg)
					continue;
				portal = tpg_portal->portal;
				log_print(LOG_DEBUG, "    portal: af = IPv%d, ip_addr = %s, port = %hu",
					  portal->af == AF_INET ? 4 : 6, portal->ip_addr, portal->port);
			}
		}
	}
}

static char inotify_event_str(const struct inotify_event *event)
{
	if (event->mask & IN_CREATE)
		return 'C';
	else if (event->mask & IN_DELETE)
		return 'D';
	else if (event->mask & IN_MODIFY)
		return 'M';
	else
		return '?';
}

static void configfs_target_handle(const struct inotify_event *event)
{
	struct target *tgt = target_find(event->name);

	if ((event->mask & IN_CREATE) && !tgt) {
		tgt = configfs_target_init(event->name);
		configfs_target_update(tgt);
		isns_target_register_later(tgt);
	} else if ((event->mask & IN_DELETE) && tgt) {
		isns_target_deregister(tgt);
		list_del(&tgt->node);
		inotify_rm_watch(inotify_fd, tgt->watch_fd);
		free(tgt);
	}
	log_print(LOG_DEBUG, "inotify[%c] %s",
		  inotify_event_str(event), event->name);
}

static void configfs_tpg_handle(const struct inotify_event *event)
{
	struct target *tgt;
	struct tpg *tpg = NULL;
	uint16_t tpg_tag;

	if (sscanf(event->name, "tpgt_%hu", &tpg_tag) != 1)
		return;

	tgt = target_find_by_watch(event->wd);
	if (!tgt)
		return;

	tpg = tpg_find_by_tag(tgt, tpg_tag);

	if ((event->mask & IN_CREATE) && !tpg) {
		tpg = configfs_tpg_init(tgt, tpg_tag);
		configfs_tpg_update(tgt, tpg);
	} else if ((event->mask & IN_DELETE) && tpg) {
		list_del(&tpg->node);
		inotify_rm_watch(inotify_fd, tpg->watch_fd);
		free(tpg);
	}
	isns_target_register_later(tgt);
	log_print(LOG_DEBUG, "inotify[%c] %s/tpg%hu",
		  inotify_event_str(event), tgt->name, tpg_tag);
}

static void configfs_tpg_subtree_handle(const struct inotify_event *event)
{
	struct target *tgt;
	struct tpg *tpg = NULL;

	list_for_each(&targets, tgt, node) {
		tpg = tpg_find_by_watch(tgt, event->wd);
		if (tpg)
			break;
	}
	if (!tpg)
		return;

	configfs_tpg_update(tgt, tpg);
	isns_target_register_later(tgt);
	log_print(LOG_DEBUG, "inotify[%c] %s/tpg%hu/%s",
		  inotify_event_str(event), tgt->name, tpg->tag, event->name);
}

void configfs_inotify_events_handle(void)
{
	ssize_t nr;
	char buf[INOTIFY_BUF_LEN];
	struct inotify_event *event;
	char *p;
	int af;
	char ip_addr[INET6_ADDRSTRLEN];
	uint16_t port;

	nr = read(inotify_fd, buf, INOTIFY_BUF_LEN);
	if (nr < 0) {
		log_print(LOG_ERR, "cannot read inotify fd %d (%d)",
			  inotify_fd, errno);
		return;
	}
	for (p = buf; p < buf + nr; ) {
		event = (struct inotify_event*) p;

		if (event->name[0] == '\0' ||
		    streq(event->name, "acls") ||
		    streq(event->name, "attrib") ||
		    streq(event->name, "auth") ||
		    streq(event->name, "fabric_statistics") ||
		    streq(event->name, "lun") ||
		    streq(event->name, "np") ||
		    streq(event->name, "param"))
			; /* Discard this event */
		else if (strstarts(event->name, "iqn."))
			configfs_target_handle(event);
		else if (strstarts(event->name, "tpgt_"))
			configfs_tpg_handle(event);
		else if (streq(event->name, "enable") ||
			 get_portal(event->name, &af, ip_addr, &port) == 0)
			configfs_tpg_subtree_handle(event);
		else
			log_print(LOG_DEBUG, "inotify[%c] %s unsupported",
				  inotify_event_str(event), event->name);

		p += sizeof(struct inotify_event) + event->len;
	}
}

struct target *target_find(const char *target_name)
{
	struct target *tgt;

	list_for_each(&targets, tgt, node) {
		if (streq(tgt->name, target_name))
			return tgt;
	}
	return NULL;
}

struct portal *portal_find(int af, const char *ip_addr, uint16_t port)
{
	struct portal *portal;

	list_for_each(&portals, portal, node) {
		if (portal->af == af &&
		    streq(portal->ip_addr, ip_addr) &&
		    portal->port == port)
			return portal;
	}
	return NULL;
}

bool tpg_has_portal(const struct tpg *tpg, const struct portal *portal)
{
	struct tpg_portal *tpg_portal;

	list_for_each(&tpg_portals, tpg_portal, node) {
		if (configfs_tpg_portal_find(tpg, portal))
			return true;
	}
	return false;
}

bool tgt_has_portal(const struct target *target, const struct portal *portal)
{
	struct tpg *tpg;

	list_for_each(&target->tpgs, tpg, node) {
		if (tpg_has_portal(tpg, portal))
			return true;
	}
	return false;
}
