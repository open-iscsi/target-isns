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

/*
 * Change the amount of time until the timer will next expire but keep
 * the current interval of the timer.
 */
int itimer_fire(int fd, unsigned int value)
{
	struct itimerspec old_timer, new_timer;

	if (timerfd_gettime(fd, &old_timer) == -1)
		return -1;
	new_timer.it_value = (struct timespec) {value, 0};
	new_timer.it_interval = old_timer.it_interval;

	return timerfd_settime(fd, 0, &new_timer, NULL);
}

time_t itimer_get_expiration(int fd)
{
	struct itimerspec timer;
	time_t expiration;

	timerfd_gettime(fd, &timer);
	expiration = timer.it_value.tv_sec;
	if (timer.it_value.tv_nsec)
		expiration += 1;

	return expiration;
}
