/*
 * (C) Copyright 2014
 * Christophe Vu-Brugier <cvubrugier@fastmail.fm>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

/*
 * This program reads an iSNS PDU from the standard input and invokes
 * the same function that `target-isns` uses to handle the iSNS PDUs
 * it receives.
 */

#include <isns.h>
#include <isns_proto.h>
#include <log.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#define EID_NAME_KEY "eid"
/* We expect iSNS PDUs to have this transaction ID: */
#define TRANSACTION_ID 0x42

extern int isns_fd;

void isns_set_fd(int isns __attribute__((unused)),
		 int scn_listen __attribute__((unused)),
		 int scn __attribute__((unused)))
{
}

int main(void)
{
	int ret;

	log_init("test-isns-fuzzing", false, LOG_DEBUG);

	ret = isns_init("127.0.0.1", ISNS_PORT);
	if (ret == -1)
		goto err_init;

	/* Create a fake query and read the response PDU from stdin. */
	if (isns_query_init(EID_NAME_KEY, TRANSACTION_ID) == NULL)
		goto err_query_init;
	isns_fd = STDIN_FILENO;
	ret = isns_handle();

err_query_init:
	isns_exit();
err_init:
	log_close();

	return ret;
}
