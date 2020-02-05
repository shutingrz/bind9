/*
 * Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 */

#pragma once

/*! \file isc/rwlock.h */

#include <inttypes.h>
#ifndef _WIN32
#include <pthread.h>
#else
#include <synchapi.h>
#endif

#include <isc/atomic.h>
#include <isc/condition.h>
#include <isc/lang.h>
#include <isc/platform.h>
#include <isc/types.h>

ISC_LANG_BEGINDECLS

typedef enum {
	isc_rwlocktype_none = 0,
	isc_rwlocktype_read,
	isc_rwlocktype_write
} isc_rwlocktype_t;

#ifndef _WIN32
#include <pthread.h>
struct isc_rwlock {
	pthread_rwlock_t rwlock;
	atomic_bool	 downgrade;
};
#else
#include <windows.h>
struct isc_rwlock {
	PSRWLOCK    rwlock;
	atomic_bool downgrade;
};
#endif

void
isc_rwlock_init(isc_rwlock_t *rwl);

void
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

void
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type);

void
isc_rwlock_downgrade(isc_rwlock_t *rwl);

void
isc_rwlock_destroy(isc_rwlock_t *rwl);

ISC_LANG_ENDDECLS
