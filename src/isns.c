/*
 * Based on code from the iSCSI Enterprise Target Project
 * http://iscsitarget.sourceforge.net
 *
 * (C) Copyright 2006
 * Fujita Tomonori <tomof@acm.org>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#define _POSIX_SOURCE
#define _POSIX_C_SOURCE 200112L
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ccan/array_size/array_size.h>
#include <ccan/list/list.h>
#include <ccan/str/str.h>

#include "configfs.h"
#include "isns_proto.h"
#include "itimer.h"
#include "log.h"

extern void isns_set_fd(int isns, int scn_listen, int scn);
extern struct list_head targets;
extern struct list_head portals;

#define BUFSIZE (1 << 18)
#define EID_NAME_KEY "eid"
#define DEFAULT_REGISTRATION_PERIOD 300
#define REGISTRATION_SETTLING_TIME 2
#define ISNS_PORTALS_CACHE_MAX 32

struct isns_io {
	char *buf;
	size_t offset;
};

struct isns_query {
	char name[ISCSI_NAME_SIZE];
	uint16_t transaction;
	struct list_node node;
};

struct isns_portals_cache {
	size_t nr_portals;
	struct {
		uint8_t ip_addr[16];
		uint32_t port;
	} portals[ISNS_PORTALS_CACHE_MAX];
};

static LIST_HEAD(query_list);
static uint16_t scn_listen_port;
int isns_fd = -1;
static int scn_listen_fd = -1;
static int scn_fd = -1;
static int registration_timer_fd = -1;
static struct isns_io isns_rx, scn_rx;
static char *rxbuf;
static uint16_t transaction;
static uint32_t registration_period = DEFAULT_REGISTRATION_PERIOD;
static char eid[HOST_NAME_MAX];
static uint8_t ip[16];
static struct sockaddr_storage ss;

static int isns_get_ip(int fd)
{
	int err;
	size_t i;
	union {
		struct sockaddr s;
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} l;
	socklen_t slen = sizeof(l.s);

	err = getsockname(fd, &l.s, &slen);
	if (err) {
		log_print(LOG_ERR, "getsockname error %s!", gai_strerror(err));
		return err;
	}

	err = getnameinfo(&l.s, sizeof(l.s),
			  eid, sizeof(eid), NULL, 0, 0);
	if (err) {
		log_print(LOG_ERR, "getnameinfo error %s!", gai_strerror(err));
		return err;
	}
	if (streq(eid, "localhost.localdomain"))
		getnameinfo(&l.s, sizeof(l.s),
			    eid, sizeof(eid), NULL, 0, NI_NUMERICHOST);

	switch (l.ss.ss_family) {
	case AF_INET:
		ip[10] = ip[11] = 0xff;
		memcpy(ip + 12, &((&l.s4)->sin_addr), 4);
		break;
	case AF_INET6:
		for (i = 0; i < ARRAY_SIZE(ip); i++)
			ip[i] = (&l.s6)->sin6_addr.s6_addr[i];
		break;
	}

	return 0;
}

static char *isns_source_attribute_get(void)
{
	static char source_attribute[ISCSI_NAME_SIZE] = "";
	struct target *target;

	if (list_empty(&targets)) {
		source_attribute[0] = '\0';
		log_print(LOG_DEBUG, "source attribute cleared");
	} else if (source_attribute[0] == '\0' ||
		   !target_find(source_attribute)) {
		target = list_top(&targets, struct target, node);
		strncpy(source_attribute, target->name, ISCSI_NAME_SIZE);
		source_attribute[ISCSI_NAME_SIZE - 1] = '\0';
		log_print(LOG_DEBUG, "source attribute set to %s",
			  source_attribute);
	}

	return source_attribute;
}

struct isns_query *isns_query_init(const char *name, uint16_t transaction)
{
	struct isns_query *query;

	if ((query = malloc(sizeof(struct isns_query))) != NULL) {
		strncpy(query->name, name, ISCSI_NAME_SIZE);
		query->name[ISCSI_NAME_SIZE - 1] = '\0';
		query->transaction = transaction;
		list_add(&query_list, &query->node);
	}

	return query;
}

static struct isns_query *isns_query_find(uint16_t transaction)
{
	struct isns_query *query, *query_next;

	list_for_each_safe(&query_list, query, query_next, node) {
		if (query->transaction == transaction) {
			return query;
		}
	}

	return NULL;
}

static struct isns_query *isns_query_pop(uint16_t transaction)
{
	struct isns_query *query;

	query = isns_query_find(transaction);
	if (query != NULL) {
		list_del(&query->node);
		return query;
	}

	return NULL;
}

static int isns_connect(void)
{
	int fd, err;

	fd = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_print(LOG_ERR, "unable to create (%s) %d!", strerror(errno),
			  ss.ss_family);
		return -1;
	}

	err = connect(fd, (struct sockaddr *) &ss, sizeof(ss));
	if (err < 0) {
		log_print(LOG_ERR, "unable to connect (%s) %d!", strerror(errno),
			  ss.ss_family);
		close(fd);
		return -1;
	}

	log_print(LOG_DEBUG, "iSNS connection opened (fd = %d)", fd);

	if (eid[0] == '\0') {
		err = isns_get_ip(fd);
		if (err) {
			close(fd);
			return -1;
		}
	}

	isns_fd = fd;
	isns_set_fd(fd, scn_listen_fd, scn_fd);

	return fd;
}

static void isns_hdr_init(struct isns_hdr *hdr, uint16_t function,
			  uint16_t length, uint16_t flags,
			  uint16_t trans, uint16_t sequence)
{
	log_print(LOG_DEBUG, "gen header %s: "
		  "len = %hu, flags = 0x%hx, tx = %hu, seq = %hu",
		  isns_function_get_abbr(function),
		  length, flags, trans, sequence);

	hdr->version = htons(0x0001);
	hdr->function = htons(function);
	hdr->length = htons(length);
	hdr->flags = htons(flags);
	hdr->transaction = htons(trans);
	hdr->sequence = htons(sequence);
}

static int isns_tlv_set(struct isns_tlv **tlv, uint32_t tag, uint32_t length,
			const void *value)
{
	if (length)
		memcpy((*tlv)->value, value, length);
	if (length % ISNS_ALIGN)
		length += (ISNS_ALIGN - (length % ISNS_ALIGN));

	(*tlv)->tag = htonl(tag);
	(*tlv)->length = htonl(length);

	length += sizeof(struct isns_tlv);
	*tlv = (struct isns_tlv *) ((char *) *tlv + length);

	return length;
}

static int isns_tlv_set_string(struct isns_tlv **tlv, uint32_t tag, const char *str)
{
	return isns_tlv_set(tlv, tag, strlen(str) + 1, str);
}

/*
 * FIXME: State Change Notification is currently disabled.
 */
#define SCN_ENABLED 0
#if SCN_ENABLED
static int isns_scn_deregister(char *name)
{
	int err;
	uint16_t flags, length = 0;
	char buf[2048];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;

	if (isns_fd == -1 && isns_connect() < 0)
		return 0;

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME, name);
	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME, name);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_SCN_DEREG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_print(LOG_ERR, "%s %d: %s", __func__, __LINE__, strerror(errno));

	return 0;
}
#endif

#if __BYTE_ORDER == __LITTLE_ENDIAN
#define set_scn_flag(x)						\
{								\
	x = (x & 0x55555555) << 1 | (x & 0xaaaaaaaa) >> 1;	\
	x = (x & 0x33333333) << 2 | (x & 0xcccccccc) >> 2;	\
	x = (x & 0x0f0f0f0f) << 4 | (x & 0xf0f0f0f0) >> 4;	\
	x = (x & 0x00ff00ff) << 8 | (x & 0xff00ff00) >> 8;	\
	x = (x & 0x0000ffff) << 16 | (x & 0xffff0000) >> 16;	\
}
#else
#define set_scn_flag(x)
#endif

static int isns_scn_register(void)
{
	int err;
	uint16_t flags, length = 0;
	uint32_t scn_flags;
	char buf[4096];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	struct target *target;

	if (list_empty(&targets))
		return 0;

	if (isns_fd == -1 && isns_connect() < 0)
		return 0;

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	target = list_top(&targets, struct target, node);

	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME, target->name);
	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME, target->name);
	length += isns_tlv_set(&tlv, 0, 0, 0);

	scn_flags = ISNS_SCN_FLAG_INITIATOR | ISNS_SCN_FLAG_OBJECT_REMOVE |
		ISNS_SCN_FLAG_OBJECT_ADDED | ISNS_SCN_FLAG_OBJECT_UPDATED;
	set_scn_flag(scn_flags);
	scn_flags = htonl(scn_flags);

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_SCN_BITMAP,
			       sizeof(scn_flags), &scn_flags);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_SCN_REG, length, flags, ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_print(LOG_ERR, "%s %d: %s", __func__, __LINE__, strerror(errno));

	return 0;
}

static int isns_eid_attr_query(void)
{
	int err;
	uint16_t flags, length = 0;
	char buf[4096];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	struct isns_query *query;

	if (list_empty(&targets))
		return 0;

	if (isns_fd == -1 && isns_connect() < 0)
		return 0;

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	query = isns_query_init(EID_NAME_KEY, ++transaction);
	if (!query)
		return 0;

	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME,
				      isns_source_attribute_get());
	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER, eid);
	length += isns_tlv_set(&tlv, 0, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_REGISTRATION_PERIOD, 0, 0);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_QRY, length, flags,
		      transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_print(LOG_ERR, "%s %d: %s", __func__, __LINE__, strerror(errno));

	return 0;
}

static int isns_attr_query(char *name)
{
	int err;
	uint16_t flags, length = 0;
	char buf[4096];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	uint32_t node = htonl(ISNS_NODE_INITIATOR);
	struct isns_query *query;

	if (list_empty(&targets))
		return 0;

	if (isns_fd == -1 && isns_connect() < 0)
		return 0;

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	query = isns_query_init(name, ++transaction);
	if (!query)
		return 0;

	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME, name);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NODE_TYPE,
			       sizeof(node), &node);
	length += isns_tlv_set(&tlv, 0, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NODE_TYPE, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_IP_ADDRESS, 0, 0);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_QRY, length, flags,
		      transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_print(LOG_ERR, "%s %d: %s", __func__, __LINE__, strerror(errno));

	return 0;
}

static void isns_ip_addr_set(const struct portal *portal, uint8_t *ip_addr)
{
	memset(ip_addr, 0, 16);

	if (streq(portal->ip_addr, "0.0.0.0") ||
	    streq(portal->ip_addr, "::")) {
		/* Use local IP address */
		memcpy(ip_addr, ip, 16);
	} else if (portal->af == AF_INET) {
		uint32_t addr;
		inet_pton(AF_INET, portal->ip_addr, &addr);

		/* RFC 4171 6.3.1: convert v4 to mapped v6 */
		ip_addr[10] = ip_addr[11] = 0xff;
		memcpy(ip_addr + 12, &addr, 4);
	} else if (portal->af == AF_INET6)
		inet_pton(AF_INET6, portal->ip_addr, ip_addr);
}

static void isns_ip_addr_get(const uint8_t *ip_addr, int *af, char *ip_str)
{
	size_t start;

	start = 12;
	*af = AF_INET;
	for (size_t i = 0; i < 12; i++) {
		if ((i <  10 && ip_addr[i] != 0x00) ||
		    (i >= 10 && ip_addr[i] != 0xFF)) {
			start = 0;
			*af = AF_INET6;
			break;
		}
	}
	inet_ntop(*af, &ip_addr[start], ip_str, INET6_ADDRSTRLEN);
}

static void isns_target_set_registered(const char *iscsi_name)
{
	struct target *target = target_find(iscsi_name);
	if (target)
		target->registered = true;
}

static void isns_portals_set_registered(uint8_t *ip_addr, uint32_t port)
{
	int af;
	char ip_str[INET6_ADDRSTRLEN];
	struct portal *portal;

	isns_ip_addr_get(ip_addr, &af, ip_str);
	portal = portal_find(af, ip_str, port);
	if (portal)
		portal->registered = true;

	/*
	 * If the IP address is the local IP address, also mark the
	 * default portal as registered.
	 */
	if (memcmp(ip_addr, ip, 16) == 0) {
		strncpy(ip_str, af == AF_INET ? "0.0.0.0" : "::", INET6_ADDRSTRLEN);
		ip_str[INET6_ADDRSTRLEN - 1] = '\0';
		portal = portal_find(af, ip_str, port);
		if (portal)
			portal->registered = true;
	}
}

#define TGT_REG_BUFSIZE		8192
#define TGT_REG_BUFTHRESH	(TGT_REG_BUFSIZE - 256)
/*
 * isns_target_register_flush - flush PDU to isns server if necessary.
 *
 * Send target register PDU once buffer threshold exceeded and reset
 * buffer to build the next continuation PDU.
 *
 * Returns length flushed or < 0 for error.
 */
static int isns_target_register_flush(struct isns_tlv **tlv, char *buf,
		size_t bufsize, uint16_t *length, uint16_t *flags,
		uint16_t *sequence)
{
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	int err;

	if (*length < TGT_REG_BUFTHRESH)
		return 0;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_REG, *length, *flags,
		      transaction, *sequence);
	log_print(LOG_DEBUG, "flushing seq %u, length %d", *sequence, *length);
	err = write(isns_fd, buf, *length + sizeof(struct isns_hdr));
	if (err < 0)
		log_print(LOG_ERR, "%s %d: %s", __func__, __LINE__,
			  strerror(errno));
	*flags &= ~ISNS_FLAG_FIRST_PDU;
	(*sequence)++;
	memset(buf, 0, bufsize);
	*tlv = (struct isns_tlv *) hdr->pdu;
	*length = 0;
	return err;
}

/*
 * isns_target_register - build / send PDU(s) to register target(s).
 *
 * An unknown amount of target groups and portals could be sent for
 * registration to the isns server.  The open-isns server can only
 * handle messages of up to 8192 bytes.  Anything larger needs to be
 * broken into multiple PDUs with proper use of ISNS_FLAG_FIRST_PDU
 * and ISNS_FLAG_LAST_PDU flags, the same transaction id and an
 * incrementing PDU sequence number.
 *
 * For each attribute appended to the message buffer, once a threshold
 * is crossed, send it over the socket, clear the buffer, and build the
 * continuation PDUs until completes.
 */
static int isns_target_register(const struct target *target)
{
	char buf[TGT_REG_BUFSIZE];
	uint16_t flags = ISNS_FLAG_CLIENT | ISNS_FLAG_FIRST_PDU, length = 0;
	uint16_t sequence = 0;
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	struct target *tgt;
	struct tpg *tpg;
	struct portal *portal;
	uint32_t node = htonl(ISNS_NODE_TARGET);
	uint32_t protocol = htonl(ISNS_ENTITY_PROTOCOL_ISCSI);
	uint32_t period = htonl(DEFAULT_REGISTRATION_PERIOD);
	int err;
	bool all_targets = target == ALL_TARGETS;
	struct isns_query *query;

	if (!all_targets && target->registered)
		flags |= ISNS_FLAG_REPLACE;

	if (all_targets) {
		if (list_empty(&targets))
			return 0;
		target = list_top(&targets, struct target, node);
	}

	if (isns_fd == -1 && isns_connect() < 0)
		return 0;

	log_print(LOG_DEBUG, "registering target %s",
		  all_targets ? "(all)" : target->name);

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	query = isns_query_init(target->name, ++transaction);
	if (!query)
		return 0;

	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME,
				      isns_source_attribute_get());
	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER, eid);
	length += isns_tlv_set(&tlv, 0, 0, 0);

	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER, eid);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ENTITY_PROTOCOL,
			       sizeof(protocol), &protocol);
	length += isns_tlv_set(&tlv, ISNS_ATTR_REGISTRATION_PERIOD,
			       sizeof(period), &period);

	/* Register the portals. */
	list_for_each(&portals, portal, node) {
		if (!target_has_portal(target, portal) && !all_targets)
			continue;

		if (portal->registered)
			continue;

		uint32_t port = htonl(portal->port);
		uint8_t ip_addr[16];
		isns_ip_addr_set(portal, ip_addr);

		length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_IP_ADDRESS, 16,
				       ip_addr);
		length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_PORT, 4, &port);
		isns_target_register_flush(&tlv, &buf[0], sizeof(buf),
					   &length, &flags, &sequence);
	}

	list_for_each(&targets, tgt, node) {
		if (tgt != target && !all_targets)
			continue;

		/* Register the iSCSI target. */
		length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME,
					      tgt->name);
		length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NODE_TYPE,
				       sizeof(node), &node);
		isns_target_register_flush(&tlv, &buf[0], sizeof(buf),
					   &length, &flags, &sequence);

		/* Register the TPGs. */
		list_for_each(&tgt->tpgs, tpg, node) {
			if (list_empty(&tpg->portals))
				continue;

			length += isns_tlv_set_string(&tlv,
					ISNS_ATTR_PG_ISCSI_NAME, tgt->name);
			isns_target_register_flush(&tlv, &buf[0], sizeof(buf),
					&length, &flags, &sequence);

			list_for_each(&portals, portal, node) {
				if (!tpg_has_portal(tpg, portal))
					continue;

				uint32_t port = htonl(portal->port);
				uint8_t ip_addr[16];
				isns_ip_addr_set(portal, ip_addr);

				length += isns_tlv_set(&tlv,
						ISNS_ATTR_PG_PORTAL_IP_ADDRESS,
						sizeof(ip_addr), &ip_addr);
				length += isns_tlv_set(&tlv,
						ISNS_ATTR_PG_PORTAL_PORT,
						sizeof(port), &port);
				isns_target_register_flush(&tlv, &buf[0],
					sizeof(buf), &length, &flags,
					&sequence);
			}
			uint32_t tag = htonl(tpg->tag);
			length += isns_tlv_set(&tlv, ISNS_ATTR_PG_TAG,
					       sizeof(tag), &tag);
			isns_target_register_flush(&tlv, &buf[0], sizeof(buf),
						   &length, &flags, &sequence);
		}
	}

	flags |= ISNS_FLAG_LAST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_REG, length, flags,
		      transaction, sequence);

	log_print(LOG_DEBUG, "sending last PDU seq %u, length %d",
		  sequence, length);
	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_print(LOG_ERR, "%s %d: %s", __func__, __LINE__, strerror(errno));

	if (scn_listen_port)
		isns_scn_register();

	return 0;
}

/*
 * iSCSI targets are not registered as soon as they appear in configfs
 * because some of their sub objects may be empty at the time.
 * For instance, a target may show up before its TPG and default portal
 * are created.
 * As a consequence, a timer is used to provide a settling time that
 * allows to register iSCSI targets later, when most of their
 * properties are known.
 */
void isns_target_register_later(struct target *tgt)
{
	time_t expiration = itimer_get_expiration(registration_timer_fd);

	if (expiration > REGISTRATION_SETTLING_TIME) {
		/* The timer next expiration is too far; trigger it sooner. */
		itimer_fire(registration_timer_fd, REGISTRATION_SETTLING_TIME);
	}
	tgt->registration_pending = true;
}

int isns_target_deregister(const struct target *target)
{
	char buf[4096];
	uint16_t flags, length = 0;
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	int err;
	bool last = list_is_singular(&targets);
	bool all_targets = target == ALL_TARGETS;

	if (isns_fd == -1 && isns_connect() < 0)
		return 0;

	log_print(LOG_DEBUG, "deregistering target %s %s",
		  all_targets ? "(all)" : target->name,
		  last ? "(last)" : "");

#if SCN_ENABLED
	isns_scn_deregister(target->name);
#endif

	memset(buf, 0, sizeof(buf));
	tlv = (struct isns_tlv *) hdr->pdu;

	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME,
				      isns_source_attribute_get());
	length += isns_tlv_set(&tlv, 0, 0, 0);

	if (last || all_targets)
		length += isns_tlv_set_string(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER, eid);
	else
		length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME, target->name);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_DEREG, length, flags,
		      ++transaction, 0);

	err = write(isns_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_print(LOG_ERR, "%s %d: %s", __func__, __LINE__, strerror(errno));

	return 0;
}

static int recv_hdr(int fd, struct isns_io *rx, const struct isns_hdr *hdr)
{
	if (rx->offset < sizeof(*hdr)) {
		ssize_t err = read(fd, rx->buf + rx->offset,
				   sizeof(*hdr) - rx->offset);
		if (err < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return -EAGAIN;
			log_print(LOG_ERR, "header read error %d %zd %d %zu",
				  fd, err, errno, rx->offset);
			return -1;
		} else if (err == 0)
			return -1;

		rx->offset += err;

		if (rx->offset < sizeof(*hdr)) {
			log_print(LOG_DEBUG, "header wait %zu %zd", rx->offset, err);
			return -EAGAIN;
		}
	}

	return 0;
}

#define get_hdr_param(hdr, function, length, flags, transaction, sequence)	\
{										\
	function = ntohs(hdr->function);					\
	length = ntohs(hdr->length);						\
	flags = ntohs(hdr->flags);						\
	transaction = ntohs(hdr->transaction);					\
	sequence = ntohs(hdr->sequence);					\
}

static int recv_pdu(int fd, struct isns_io *rx, struct isns_hdr *hdr)
{
	uint16_t function, length, flags, transaction, sequence;
	int err;

	err = recv_hdr(fd, rx, hdr);
	if (err)
		return err;

	/* Now we got a complete header */
	get_hdr_param(hdr, function, length, flags, transaction, sequence);
	log_print(LOG_DEBUG, "got header %s: "
		  "len = %hu, flags = 0x%hx, tx = %hu, seq = %hu",
		  isns_function_get_abbr(function),
		  length, flags, transaction, sequence);

	if (length + sizeof(*hdr) > BUFSIZE) {
		log_print(LOG_ERR, "FIXME we cannot handle this yet %u!", length);
		return -1;
	}

	if (rx->offset < length + sizeof(*hdr)) {
		err = read(fd, rx->buf + rx->offset,
			   length + sizeof(*hdr) - rx->offset);
		if (err < 0) {
			if (errno == EAGAIN || errno == EINTR)
				return -EAGAIN;
			log_print(LOG_ERR, "pdu read error %d %d %d %zu",
				  fd, err, errno, rx->offset);
			return -1;
		} else if (err == 0)
			return -1;

		rx->offset += err;

		if (rx->offset < length + sizeof(*hdr)) {
			log_print(LOG_ERR, "pdu wait %zu %d", rx->offset, err);
			return -EAGAIN;
		}
	}

	/* Now we got everything. */
	rx->offset = 0;

	return 0;
}

#define print_unknown_pdu(hdr)						\
{									\
	uint16_t function, length, flags, transaction, sequence;	\
	get_hdr_param(hdr, function, length, flags, transaction,	\
		      sequence)						\
	log_print(LOG_ERR, "%s %d: unknown function %x %u %x %u %u",	\
		  __func__, __LINE__,				\
		  function, length, flags, transaction, sequence);	\
}

static char *print_scn_pdu(const struct isns_hdr *hdr)
{
	struct isns_tlv *tlv = (struct isns_tlv *) hdr->pdu;
	uint16_t length = ntohs(hdr->length);
	char *name = NULL;

	while (length) {
		uint32_t vlen = ntohl(tlv->length);

		if (vlen + sizeof(*tlv) > length)
			vlen = length - sizeof(*tlv);

		switch (ntohl(tlv->tag)) {
		case ISNS_ATTR_ISCSI_NAME:
			if (vlen) {
				size_t slen = vlen - 1;

				if (slen >= ISCSI_NAME_SIZE)
					slen = ISCSI_NAME_SIZE - 1;

				*((char *) tlv->value + slen) = 0;

				log_print(LOG_ERR, "scn name: %u, %s", vlen,
					  (char *) tlv->value);

				if (!name)
					name = (char *) tlv->value;
			}
			break;
		case ISNS_ATTR_TIMESTAMP:
/*			if (vlen == 8)
				log_print(LOG_ERR, "%u : %u : %" PRIx64, ntohl(tlv->tag),
					  vlen, *((uint64_t *) tlv->value));
*/
			break;
		case ISNS_ATTR_ISCSI_SCN_BITMAP:
			if (vlen == 4)
				log_print(LOG_ERR, "scn bitmap : %x",
					  *((uint32_t *) tlv->value));
			break;
		}

		length -= (sizeof(*tlv) + vlen);
		tlv = (struct isns_tlv *) ((char *) tlv->value + vlen);
	}

	return name;
}

static void isns_registration_set_period(uint32_t period);

static void isns_rsp_handle(const struct isns_hdr *hdr)
{
	struct isns_tlv *tlv;
	uint16_t length = ntohs(hdr->length);
	uint16_t flags = ntohs(hdr->flags);
	uint16_t transaction = ntohs(hdr->transaction);
	uint32_t status;
	struct isns_query *query;
	char *iscsi_name = NULL;
	uint8_t ip_addr[16];
	uint32_t port;
	uint32_t period;

	/* Only pop the query from the list if the last PDU is received. */
	if (flags & ISNS_FLAG_LAST_PDU)
		query = isns_query_pop(transaction);
	else
		query = isns_query_find(transaction);
	if (!query) {
		log_print(LOG_ERR, "unknown transaction %u", transaction);
		return;
	}

	if (flags & ISNS_FLAG_FIRST_PDU) {
		status = ntohl(hdr->pdu[0]);
		if (status) {
			log_print(LOG_ERR,
				"error in response (status = %" PRIu32 ")",
				status);
			goto free_query;
		}
	}

	if (query->name[0] == '\0') {
		log_print(LOG_DEBUG, "%s %d: skip %u",
			  __func__, __LINE__, transaction);
		goto free_query;
	}

	if (!streq(query->name, EID_NAME_KEY) && !target_find(query->name)) {
		log_print(LOG_ERR, "%s %d: unknown query name %s",
			  __func__, __LINE__, query->name);
		goto free_query;
	}

	/* Skip status on the first PDU. */
	if (flags & ISNS_FLAG_FIRST_PDU) {
		tlv = (struct isns_tlv *) ((char *) hdr->pdu + 4);

		if (length < 4)
			goto free_query;

		length -= 4;
	} else {
		tlv = (struct isns_tlv *)hdr->pdu;
	}

	while (length) {
		uint32_t tag = ntohl(tlv->tag);
		uint32_t vlen = ntohl(tlv->length);

		if (vlen + sizeof(*tlv) > length)
			vlen = length - sizeof(*tlv);

		switch (tag) {
		case ISNS_ATTR_DELIMITER:
		case ISNS_ATTR_ENTITY_IDENTIFIER:
			break;
		case ISNS_ATTR_REGISTRATION_PERIOD:
			if (vlen != 4)
				break;
			period = ntohl(*(tlv->value));
			isns_registration_set_period(period);
			break;
		case ISNS_ATTR_ISCSI_NAME:
			if (vlen == 0) {
				iscsi_name = NULL;
				break;
			}
			size_t slen = vlen - 1;
			if (slen >= ISCSI_NAME_SIZE)
				slen = ISCSI_NAME_SIZE - 1;
			*((char *) tlv->value + slen) = '\0';
			iscsi_name = (char *) tlv->value;
			isns_target_set_registered(iscsi_name);
			break;
		case ISNS_ATTR_ISCSI_NODE_TYPE:
			if (vlen != 4)
				break;
			if (!iscsi_name)
				break;
			uint32_t node_type = ntohl(*(tlv->value));
			switch (node_type) {
			case ISNS_NODE_CONTROL:
				log_print(LOG_DEBUG, "%s is a control node", iscsi_name);
				break;
			case ISNS_NODE_INITIATOR:
				log_print(LOG_DEBUG, "%s is an initiator", iscsi_name);
				break;
			case ISNS_NODE_TARGET:
				log_print(LOG_DEBUG, "%s is a target", iscsi_name);
				break;
			}
			break;
		case ISNS_ATTR_PORTAL_IP_ADDRESS:
			if (vlen == 16)
				memcpy(ip_addr, tlv->value, 16);
			else
				memset(ip_addr, 0, 16);
			break;
		case ISNS_ATTR_PORTAL_PORT:
			if (vlen != 4)
				break;
			port = ntohl(*(tlv->value));
			isns_portals_set_registered(ip_addr, port);
			break;
		default:
			iscsi_name = NULL;
			break;
		}

		length -= (sizeof(*tlv) + vlen);
		tlv = (struct isns_tlv *) ((char *) tlv->value + vlen);
	}

free_query:
	if (flags & ISNS_FLAG_LAST_PDU)
		free(query);
}

int isns_handle(void)
{
	int err;
	struct isns_io *rx = &isns_rx;
	struct isns_hdr *hdr = (struct isns_hdr *) rx->buf;
	uint16_t function;

	err = recv_pdu(isns_fd, rx, hdr);
	if (err) {
		if (err == -EAGAIN)
			return err;
		log_print(LOG_DEBUG, "iSNS connection closed (fd = %d)", isns_fd);
		isns_set_fd(-1, scn_listen_fd, scn_fd);
		isns_fd = -1;
		return err;
	}

	function = ntohs(hdr->function);
	if (isns_function_is_rsp(function))
		isns_rsp_handle(hdr);

	return 0;
}

static int scn_accept_connection(void)
{
	struct sockaddr_storage from;
	socklen_t slen;
	int fd, err, opt = 1;

	slen = sizeof(from);
	fd = accept(scn_listen_fd, (struct sockaddr *) &from, &slen);
	if (fd < 0) {
		log_print(LOG_ERR, "%s %d: accept error %s", __func__, __LINE__,
			  strerror(errno));
		return -errno;
	}
	log_print(LOG_ERR, "Accept scn connection %d", fd);

	err = setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
	if (err)
		log_print(LOG_ERR, "%s %d: %s\n", __func__, __LINE__,
			  strerror(errno));
	/* not critical, so ignore. */

	scn_fd = fd;
	isns_set_fd(isns_fd, scn_listen_fd, scn_fd);

	return 0;
}

static void send_scn_rsp(char *name, uint16_t transaction)
{
	char buf[1024];
	struct isns_hdr *hdr = (struct isns_hdr *) buf;
	struct isns_tlv *tlv;
	uint16_t flags, length = 0;
	int err;

	memset(buf, 0, sizeof(buf));
	*((uint32_t *) hdr->pdu) = 0;
	tlv = (struct isns_tlv *) ((char *) hdr->pdu + 4);
	length +=4;

	length += isns_tlv_set_string(&tlv, ISNS_ATTR_ISCSI_NAME, name);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	isns_hdr_init(hdr, ISNS_FUNC_SCN_RSP, length, flags, transaction, 0);

	err = write(scn_fd, buf, length + sizeof(struct isns_hdr));
	if (err < 0)
		log_print(LOG_ERR, "%s %d: %s", __func__, __LINE__, strerror(errno));
}

int isns_scn_handle(bool is_accept)
{
	int err;
	struct isns_io *rx = &scn_rx;
	struct isns_hdr *hdr = (struct isns_hdr *) rx->buf;
	uint16_t function, transaction;
	char *name = NULL;

	log_print(LOG_ERR, "%s %d: %d", __func__, __LINE__, is_accept);

	if (is_accept)
		return scn_accept_connection();

	err = recv_pdu(scn_fd, rx, hdr);
	if (err) {
		if (err == -EAGAIN)
			return err;
		log_print(LOG_DEBUG, "%s %d: close connection %d", __func__, __LINE__,
			  scn_fd);
		isns_set_fd(isns_fd, scn_listen_fd, -1);
		scn_fd = -1;
		return err;
	}

	function = ntohs(hdr->function);
	transaction = ntohs(hdr->transaction);

	switch (function) {
	case ISNS_FUNC_SCN:
		name = print_scn_pdu(hdr);
		break;
	default:
		print_unknown_pdu(hdr);
	}

	if (name) {
		send_scn_rsp(name, transaction);
		isns_attr_query(name);
	}

	return 0;
}

#if SCN_ENABLED
static int scn_init(char *addr __attribute__ ((unused)))
{
	int fd, opt, err;
	union {
		struct sockaddr s;
		struct sockaddr_storage ss;
		struct sockaddr_in s4;
		struct sockaddr_in6 s6;
	} l;
	socklen_t slen;

	fd = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_print(LOG_ERR, "%s %d: %s\n", __func__, __LINE__, strerror(errno));
		return -errno;
	}

	opt = 1;
	if (ss.ss_family == AF_INET6) {
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt));
		if (err)
			log_print(LOG_ERR, "%s %d: %s\n", __func__, __LINE__,
				  strerror(errno));
		goto out;
	}

	err = listen(fd, 5);
	if (err) {
		log_print(LOG_ERR, "%s %d: %s\n", __func__, __LINE__, strerror(errno));
		goto out;
	}

	slen = sizeof(l.s);
	err = getsockname(fd, &l.s, &slen);
	if (err) {
		log_print(LOG_ERR, "%s %d: %s\n", __func__, __LINE__, strerror(errno));
		goto out;
	}

	/* protocol independent way ? */
	if (l.ss.ss_family == AF_INET6)
		scn_listen_port = ntohs((&l.s6)->sin6_port);
	else
		scn_listen_port = ntohs((&l.s4)->sin_port);

	log_print(LOG_DEBUG, "SCN listen port is %hu", scn_listen_port);
out:
	if (err)
		close(fd);
	else {
		scn_listen_fd = fd;
		isns_set_fd(isns_fd, scn_listen_fd, scn_fd);
	}

	return err;
}
#endif

int isns_registration_timer_init(void)
{
	registration_timer_fd = itimer_create();
	if (registration_timer_fd != -1)
		itimer_start(registration_timer_fd, registration_period - 10);
	return registration_timer_fd;
}

void isns_registration_refresh(void)
{
	struct target *tgt;
	bool target_registered;
	uint64_t count;

	if (read(registration_timer_fd, &count, sizeof(count)) == -1)
		return;

	target_registered = false;
	list_for_each(&targets, tgt, node) {
		if (tgt->registration_pending) {
			isns_target_register(tgt);
			tgt->registration_pending = false;
			target_registered = true;
		}
	}

	if (!target_registered) {
		/* Registration period is close to expiration */
		log_print(LOG_DEBUG, "refreshing registration");
		isns_eid_attr_query();
	}
}

static void isns_registration_set_period(uint32_t period)
{
	if (period == registration_period)
		return;

	registration_period = period;
	log_print(LOG_DEBUG, "registration period is now %" PRIu32 " seconds",
		  period);
	itimer_start(registration_timer_fd, registration_period - 10);
}

int isns_init(const char *addr, uint16_t isns_port)
{
	int err;
	char port[8];
	struct addrinfo hints, *res;

	if (!addr || addr[0] == '\0') {
		log_print(LOG_ERR, "no iSNS server address given");
		return -1;
	}

	log_print(LOG_INFO, "iSNS server is %s:%hu", addr, isns_port);

	snprintf(port, sizeof(port), "%hu", isns_port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	err = getaddrinfo(addr, (char *) &port, &hints, &res);
	if (err) {
		log_print(LOG_ERR, "getaddrinfo error %s, %s", gai_strerror(err), addr);
		return -1;
	}
	memcpy(&ss, res->ai_addr, sizeof(*res->ai_addr));
	freeaddrinfo(res);

	rxbuf = calloc(2, BUFSIZE);
	if (!rxbuf) {
		log_print(LOG_ERR, "oom!");
		return -1;
	}

#if SCN_ENABLED
	scn_init(addr);
#endif

	isns_rx.buf = rxbuf;
	isns_rx.offset = 0;
	scn_rx.buf = rxbuf + BUFSIZE;
	scn_rx.offset = 0;

	return 0;
}

void isns_start(void)
{
	isns_target_register(ALL_TARGETS);
}

void isns_stop(void)
{
	isns_target_deregister(ALL_TARGETS);
}

void isns_exit(void)
{
	/* We can't receive events any more. */
	isns_set_fd(-1, -1, -1);

	free(rxbuf);
}
