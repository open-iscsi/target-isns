/*
 * This file is part of target-isns.
 *
 * Copyright (C) 2013 Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * target-isns is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * target-isns is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with target-isns; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef __ISNS_H__
#define __ISNS_H__

int isns_handle(bool is_timeout, int *timeout);

int isns_scn_handle(bool is_accept);

int isns_init(char *addr);

void isns_exit(void);

#endif
