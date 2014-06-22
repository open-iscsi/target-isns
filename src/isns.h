/*
 * (C) Copyright 2013
 * Christophe Vu-Brugier <cvubrugier@yahoo.fr>
 *
 * SPDX-License-Identifier:	GPL-2.0+
 */

#pragma once

int isns_handle(void);

int isns_scn_handle(bool is_accept);

int isns_init(const char *addr, uint16_t isns_port);

void isns_start(void);

void isns_stop(void);

void isns_exit(void);

void isns_target_register(const struct target *target);

void isns_target_deregister(const struct target *target);

int isns_registration_timer_init(void);

void isns_registration_refresh(void);
