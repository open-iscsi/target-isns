/*
 * (C) Copyright 2014
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

/*
 * This file defines interval timer functions based on timerfd.
 */

#define _POSIX_C_SOURCE	200809L

#include <sys/timerfd.h>

int itimer_create(void)
{
	return timerfd_create(CLOCK_MONOTONIC, 0);
}

int itimer_start(int fd, unsigned int interval)
{
	struct itimerspec timer = {
		.it_interval = {interval, 0},
		.it_value = {interval, 0},
	};
	return timerfd_settime(fd, 0, &timer, NULL);
}

int itimer_stop(int fd)
{
	return itimer_start(fd, 0);
}
