/*
 * (C) Copyright 2014
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#ifndef __ITIMER_H__
#define __ITIMER_H__

int itimer_create(void);

int itimer_start(int fd, unsigned int interval);

int itimer_stop(int fd);

#endif
