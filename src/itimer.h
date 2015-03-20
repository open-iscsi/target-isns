/*
 * (C) Copyright 2014
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#pragma once

int itimer_create(void);

int itimer_start(int fd, unsigned int interval);

int itimer_stop(int fd);

int itimer_fire(int fd, unsigned int value);

time_t itimer_get_expiration(int fd);
