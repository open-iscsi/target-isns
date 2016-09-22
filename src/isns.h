/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@fastmail.fm>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#pragma once

#include <inttypes.h>
#include <stdbool.h>

struct isns_query;
struct target;

struct isns_query *isns_query_init(const char *name, uint16_t transaction);

int isns_handle(void);

int isns_scn_handle(bool is_accept);

int isns_init(const char *addr, uint16_t isns_port);

void isns_start(void);

void isns_stop(void);

void isns_exit(void);

void isns_target_register_later(const struct target *target);

void isns_target_deregister(const struct target *target);

int isns_registration_timer_init(void);

void isns_registration_refresh(void);
