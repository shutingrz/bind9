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

/*! \file */

#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#ifndef _WIN32
#include <pthread.h>
#else
#include <synchapi.h>
#endif

#include <errno.h>

#include <isc/atomic.h>
#include <isc/magic.h>
#include <isc/platform.h>
#include <isc/print.h>
#include <isc/rwlock.h>
#include <isc/util.h>

void
isc_rwlock_init(isc_rwlock_t *rwl) {
#ifndef _WIN32
	REQUIRE(pthread_rwlock_init(&rwl->rwlock, NULL) == 0);
#else
	InitializeSRWLock(&rwl->rwlock);
#endif
	atomic_init(&rwl->downgrade, false);
}

void
isc_rwlock_lock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	switch (type) {
	case isc_rwlocktype_read:
#ifndef _WIN32
		REQUIRE(pthread_rwlock_rdlock(&rwl->rwlock) == 0);
#else
		AcquireSRWLockShared(&rwl->rwlock);
#endif
		break;
	case isc_rwlocktype_write:
		while (true) {
#ifndef _WIN32
			REQUIRE(pthread_rwlock_wrlock(&rwl->rwlock) == 0);
#else
			AcquireSRWLockExclusive(&rwl->rwlock);
#endif
			/* Unlock if in middle of downgrade operation */
			if (atomic_load_acquire(&rwl->downgrade)) {
#ifndef _WIN32
				REQUIRE(pthread_rwlock_unlock(&rwl->rwlock) ==
					0);
#else
				ReleaseSRWLockExclusive(&rwl->rwlock);
#endif
				while (atomic_load_acquire(&rwl->downgrade))
					;
				continue;
			}
			break;
		}
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

isc_result_t
isc_rwlock_trylock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
	int ret = 0;
	switch (type) {
	case isc_rwlocktype_read:
#ifndef _WIN32
		ret = pthread_rwlock_tryrdlock(&rwl->rwlock);
#else
		ret = TryAcquireSRWLockShared(&rwl->rwlock) ? 0 : EBUSY;
#endif
		break;
	case isc_rwlocktype_write:
#ifndef _WIN32
		ret = pthread_rwlock_trywrlock(&rwl->rwlock);
#else
		ret = TryAcquireSRWLockExclusive(&rwl->rwlock) ? 0 : EBUSY;
#endif
		if ((ret == 0) && atomic_load_acquire(&rwl->downgrade)) {
#ifndef _WIN32
			REQUIRE(pthread_rwlock_unlock(&rwl->rwlock) == 0);
#else
			ReleaseSRWLockExclusive(&rwl->rwlock);
#endif
			return (ISC_R_LOCKBUSY);
		}
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}

	switch (ret) {
	case 0:
		return (ISC_R_SUCCESS);
	case EBUSY:
		return (ISC_R_LOCKBUSY);
	case EAGAIN:
		return (ISC_R_LOCKBUSY);
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
}

void
isc_rwlock_unlock(isc_rwlock_t *rwl, isc_rwlocktype_t type) {
#ifndef _WIN32
	UNUSED(type);
	REQUIRE(pthread_rwlock_unlock(&rwl->rwlock) == 0);
#else
	switch (type) {
	case isc_rwlocktype_read:
		ReleaseSRWLockShared(&rwl->rwlock);
		break;
	case isc_rwlocktype_write:
		ReleaseSRWLockExclusive(&rwl->rwlock);
		break;
	default:
		INSIST(0);
		ISC_UNREACHABLE();
	}
#endif
}

void
isc_rwlock_downgrade(isc_rwlock_t *rwl) {
	atomic_store_release(&rwl->downgrade, true);
	isc_rwlock_unlock(rwl, isc_rwlocktype_write);
	isc_rwlock_lock(rwl, isc_rwlocktype_read);
	atomic_store_release(&rwl->downgrade, false);
}

void
isc_rwlock_destroy(isc_rwlock_t *rwl) {
#ifndef _WIN32
	pthread_rwlock_destroy(&rwl->rwlock);
#else
	UNUSED(rwl);
#endif
}
