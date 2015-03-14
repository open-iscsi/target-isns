/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#define _POSIX_C_SOURCE 1
#include <ccan/array_size/array_size.h>
#include <ccan/daemonize/daemonize.h>
#include <ccan/str/str.h>
#include <getopt.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>
#include "configfs.h"
#include "isns.h"
#include "log.h"
#include "util.h"
#include "version.h"

#define PROGNAME "target-isns"

enum {
	EPOLL_INOTIFY = 0,		/* config FS notifications */
	EPOLL_SIGNAL,			/* signal handling */
	EPOLL_ISNS,			/* iSNS (de)register commands */
	EPOLL_SCN_LISTEN,		/* SCN connection */
	EPOLL_SCN,			/* SCN notifications */
	EPOLL_REGISTRATION_TIMER,	/* iSNS registration timer */
	EPOLL_MAX_FD
} epoll_id;

static int epoll_fd;
static int epoll_set[EPOLL_MAX_FD];
static struct epoll_event epoll_events[EPOLL_MAX_FD];

static void print_usage(void)
{
	printf("Usage: " PROGNAME " [OPTIONS]\n"
	       "  -i, --isns-server  Set the IP address of the iSNS server.\n"
	       "  -p, --isns-port    Set the remote port for iSNS server.\n"
	       "  -d, --debug        Increase the debugging level (implies -f).\n"
	       "  -f, --foreground   Run in the foreground.\n"
	       "  -v, --version      Print version information.\n"
	       "  -h, --help         Print this message.\n");
}

static void epoll_init_fds(void)
{
	for (size_t i = 0; i < ARRAY_SIZE(epoll_set); i++)
		epoll_set[i] = -1;
}

static void epoll_set_fd(int epoll_id, int fd)
{
	int old_fd = epoll_set[epoll_id];

	if (fd == old_fd)
		return;

	if (old_fd != -1) {
		epoll_ctl(epoll_fd, EPOLL_CTL_DEL, old_fd, NULL);
		close(old_fd);
	}

	if (fd != -1) {
		struct epoll_event *ev = &epoll_events[epoll_id];
		ev->events = EPOLLIN;
		ev->data.fd = fd;
		epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, ev);
	}
	epoll_set[epoll_id] = fd;
}

void isns_set_fd(int isns, int scn_listen, int scn)
{
	epoll_set_fd(EPOLL_ISNS, isns);
	epoll_set_fd(EPOLL_SCN_LISTEN, scn_listen);
	epoll_set_fd(EPOLL_SCN, scn);
}

static int signal_init(void)
{
	sigset_t mask;

	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, NULL);

	return signalfd(-1, &mask, 0);
}

static bool signal_is_quit(int fd)
{
	struct signalfd_siginfo siginfo;

	if (read(fd, &siginfo, sizeof(siginfo)) < (ssize_t) sizeof(siginfo))
		return false;

	if (siginfo.ssi_signo == SIGUSR1)
		configfs_show();

	return siginfo.ssi_signo == SIGINT ||
		siginfo.ssi_signo == SIGQUIT ||
		siginfo.ssi_signo == SIGTERM;
}

int main(int argc, char *argv[])
{
	char optstring[] = "i:p:dfvh";
	struct option longopts[] = {
		{"isns-server", 1, NULL, 'i'},
		{"isns-port",   1, NULL, 'p'},
		{"debug",       0, NULL, 'd'},
		{"foreground",  0, NULL, 'f'},
		{"version",     0, NULL, 'v'},
		{"help",        0, NULL, 'h'},
		{NULL,          0, NULL, 0}
        };
	int option;
	int longindex = 0;
	int ifd = -1, sfd = -1, tfd = -1;
	struct epoll_event events[EPOLL_MAX_FD];
	ssize_t nr_events;
	bool daemon = true;
	int ret = EXIT_FAILURE;

	conffile_read();

	while ((option = getopt_long(argc, argv, optstring, longopts,
				     &longindex)) != -1) {
		switch (option) {
		case 'i':
			;
			const size_t sz = sizeof(config.isns_server);
			strncpy(config.isns_server, optarg, sz);
			config.isns_server[sz - 1] = '\0';
			break;
		case 'p':
			sscanf(optarg, "%hu", &config.isns_port);
			break;
		case 'd':
			config.log_level = LOG_DEBUG;
			daemon = false;
			break;
		case 'f':
			daemon = false;
			break;
		case 'v':
			printf(PROGNAME " version " VERSION "\n");
			exit(EXIT_SUCCESS);
			break;
		case 'h':
			print_usage();
			exit(EXIT_SUCCESS);
			break;
		case ':':
		case '?':
			exit(EXIT_FAILURE);
			break;
		}
	}

	if (!configfs_iscsi_path_exists()) {
		fprintf(stderr,
			"Error: configfs is not mounted or the "
			"target and iSCSI modules are not loaded.\n");
		exit(EXIT_FAILURE);
	}

	if (daemon) {
		daemonize();
		pidfile_create();
	}

	log_init(PROGNAME, daemon, config.log_level);
	log_print(LOG_INFO, PROGNAME " version " VERSION " started");

	epoll_init_fds();
	if (isns_init(config.isns_server, config.isns_port) == -1) {
		log_print(LOG_ERR, "failed to initialize iSNS client");
		goto err_init;
	}

	if ((epoll_fd = epoll_create1(0)) == -1) {
		log_print(LOG_ERR, "failed to create epoll instance");
		goto err_epoll_fd;
	}

	if ((ifd = configfs_init()) == -1) {
		log_print(LOG_ERR, "failed to create inotify instance");
		goto err_ifd;
	}
	epoll_set_fd(EPOLL_INOTIFY, ifd);

	if ((tfd = isns_registration_timer_init()) == -1) {
		log_print(LOG_ERR, "failed to create timerfd instance");
		goto err_tfd;
	}
	epoll_set_fd(EPOLL_REGISTRATION_TIMER, tfd);

	if ((sfd = signal_init()) == -1) {
		log_print(LOG_ERR, "failed to create signalfd instance");
		goto err_sfd;
	}
	epoll_set_fd(EPOLL_SIGNAL, sfd);

	isns_start();
	while (true) {
		nr_events = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);

		for (int i = 0; i < nr_events; i++) {
			int fd = events[i].data.fd;

			if (fd == epoll_set[EPOLL_SIGNAL]) {
				if (signal_is_quit(fd))
					goto quit;
			} else if (fd == epoll_set[EPOLL_INOTIFY])
				configfs_handle_events();
			else if (fd == epoll_set[EPOLL_REGISTRATION_TIMER])
				isns_registration_refresh();
			else if (fd == epoll_set[EPOLL_ISNS])
				isns_handle();
			else if (fd == epoll_set[EPOLL_SCN_LISTEN])
				isns_scn_handle(true);
			else if (fd == epoll_set[EPOLL_SCN])
				isns_scn_handle(false);
		}
	}

quit:
	ret = EXIT_SUCCESS;
	isns_stop();
	sleep(1);
	close(sfd);
err_sfd:
	close(tfd);
err_tfd:
	configfs_cleanup(); /* closes ifd */
err_ifd:
	close(epoll_fd);
err_epoll_fd:
	isns_exit();
err_init:
	log_print(LOG_INFO, PROGNAME " stopped");
	log_close();
	if (daemon)
		pidfile_remove();

	return ret;
}
