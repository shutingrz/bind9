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

/*! \file */

#include <stdio.h>

#include <isc/lang.h>
#include <isc/result.h>

/*!
 * Define ISC_MUTEX_PROFILE to turn on profiling of mutexes by line.  When
 * enabled, isc_mutex_stats() can be used to print a table showing the
 * number of times each type of mutex was locked and the amount of time
 * waiting to obtain the lock.
 */
#ifndef ISC_MUTEX_PROFILE
#define ISC_MUTEX_PROFILE 0
#endif /* ifndef ISC_MUTEX_PROFILE */

#if HAVE_PTHREAD

#include <pthread.h>

ISC_LANG_BEGINDECLS

/*!
 * Supply mutex attributes that enable deadlock detection
 * (helpful when debugging).  This is system dependent and
 * currently only supported on NetBSD.
 */
#if ISC_MUTEX_DEBUG && defined(__NetBSD__) && defined(PTHREAD_MUTEX_ERRORCHECK)
extern pthread_mutexattr_t isc__mutex_attrs;
#define ISC__MUTEX_ATTRS &isc__mutex_attrs
#else /* if ISC_MUTEX_DEBUG && defined(__NetBSD__) && \
       * defined(PTHREAD_MUTEX_ERRORCHECK) */
#define ISC__MUTEX_ATTRS NULL
#endif /* if ISC_MUTEX_DEBUG && defined(__NetBSD__) && \
	* defined(PTHREAD_MUTEX_ERRORCHECK) */

#if ISC_MUTEX_PROFILE
typedef struct isc_mutexstats isc_mutexstats_t;

typedef struct {
	pthread_mutex_t	  mutex; /*%< The actual mutex. */
	isc_mutexstats_t *stats; /*%< Mutex statistics. */
} isc_mutex_t;

#define isc_mutex_init(mp)   isc_mutex_init_profile((mp), __FILE__, __LINE__)
#define isc_mutex_lock(mp)   isc_mutex_lock_profile((mp), __FILE__, __LINE__)
#define isc_mutex_unlock(mp) isc_mutex_unlock_profile((mp), __FILE__, __LINE__)

#define isc_mutex_trylock(mp)                                         \
	((pthread_mutex_trylock((&(mp)->mutex)) == 0) ? ISC_R_SUCCESS \
						      : ISC_R_LOCKBUSY)
#define isc_mutex_destroy(mp) \
	RUNTIME_CHECK(pthread_mutex_destroy((&(mp)->mutex)) == 0)
#define isc_mutex_stats(fp) isc_mutex_statsprofile(fp);

void
isc_mutex_init_profile(isc_mutex_t *mp, const char *_file, int _line);
isc_result_t
isc_mutex_lock_profile(isc_mutex_t *mp, const char *_file, int _line);
isc_result_t
isc_mutex_unlock_profile(isc_mutex_t *mp, const char *_file, int _line);

void
isc_mutex_statsprofile(FILE *fp);

void
isc_mutex_init_errcheck(isc_mutex_t *mp);

#else /* if ISC_MUTEX_PROFILE */
typedef pthread_mutex_t isc_mutex_t;

#if ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK)
#define isc_mutex_init(mp) isc_mutex_init_errcheck((mp))
#else /* if ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK) */
#define isc_mutex_init(mp) isc__mutex_init((mp), __FILE__, __LINE__)
void
isc__mutex_init(isc_mutex_t *mp, const char *file, unsigned int line);
#endif /* if ISC_MUTEX_DEBUG && defined(PTHREAD_MUTEX_ERRORCHECK) */

#define isc_mutex_lock(mp) \
	((pthread_mutex_lock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)
#define isc_mutex_unlock(mp) \
	((pthread_mutex_unlock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)
#define isc_mutex_trylock(mp) \
	((pthread_mutex_trylock((mp)) == 0) ? ISC_R_SUCCESS : ISC_R_LOCKBUSY)
#define isc_mutex_destroy(mp) RUNTIME_CHECK(pthread_mutex_destroy((mp)) == 0)

#define isc_mutex_stats(fp)

#endif /* if ISC_MUTEX_PROFILE */

ISC_LANG_ENDDECLS

#elif HAVE_C11_THREAD_SUPPORT

#include <threads.h>

ISC_LANG_BEGINDECLS

typedef mtx_t isc_mutex_t;

#define isc_mutex_init(mutex)                                         \
	switch (mtx_init(mutex, mtx_plain)) {                         \
	case thrd_success:                                            \
		break;                                                \
	default:                                                      \
		isc_error_fatal(__FILE__, __LINE__,                   \
				"mtx_init failed: Unexpected error"); \
	}

#define isc_mutex_lock(mutex) \
	((mtx_lock(mutex) == thrd_success) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_mutex_unlock(mp) \
	((mtx_unlock((mp)) == thrd_success) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#define isc_mutex_trylock(mutex)                                         \
	({                                                               \
		isc_result_t __ret;                                      \
		switch (mtx_trylock(mutex)) {                            \
		case thrd_success:                                       \
			__ret = ISC_R_SUCCESS;                           \
			break;                                           \
		case thrd_busy:                                          \
			__ret = ISC_R_LOCKBUSY;                          \
			break;                                           \
		default:                                                 \
			isc_error_fatal(                                 \
				__FILE__, __LINE__,                      \
				"mtx_trylock failed: Unexpected error"); \
		}                                                        \
		__ret;                                                   \
	})

#define isc_mutex_destroy(mutex) mtx_destroy(mutex)
#define isc_mutex_stats(fp)

ISC_LANG_ENDDECLS

#endif
