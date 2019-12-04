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

#if HAVE_THREADS_H
#include <threads.h>
#endif

#include <isc/lang.h>
#include <isc/result.h>

#if HAVE_PTHREAD

#include <pthread.h>

#if defined(HAVE_PTHREAD_NP_H)
#include <pthread_np.h>
#endif /* if defined(HAVE_PTHREAD_NP_H) */

ISC_LANG_BEGINDECLS

typedef pthread_t isc_thread_t;
typedef void *	  isc_threadresult_t;
typedef void *	  isc_threadarg_t;
typedef isc_threadresult_t (*isc_threadfunc_t)(isc_threadarg_t);

void
isc_thread_create(isc_threadfunc_t, isc_threadarg_t, isc_thread_t *);

void
isc_thread_join(isc_thread_t thread, isc_threadresult_t *result);

void
isc_thread_setconcurrency(unsigned int level);

void
isc_thread_yield(void);

void
isc_thread_setname(isc_thread_t thread, const char *name);

isc_result_t
isc_thread_setaffinity(int cpu);

#define isc_thread_self (unsigned long)pthread_self

ISC_LANG_ENDDECLS

#elif HAVE_C11_THREAD_SUPPORT

ISC_LANG_BEGINDECLS

typedef thrd_t isc_thread_t;
typedef int    isc_threadresult_t;
typedef void * isc_threadarg_t;
typedef isc_threadresult_t (*isc_threadfunc_t)(isc_threadarg_t);

#define isc_thread_create(func, arg, thr)                                     \
	{                                                                     \
		switch (thrd_create(thr, func, arg)) {                        \
		case thrd_success:                                            \
			break;                                                \
		case thrd_nomem:                                              \
			isc_error_fatal(__FILE__, __LINE__,                   \
					"mtx_init failed: Out of memory");    \
		default:                                                      \
			isc_error_fatal(__FILE__, __LINE__,                   \
					"mtx_init failed: Unexpected error"); \
		}                                                             \
	}

#define isc_thread_join(thr, res)                                             \
	{                                                                     \
		switch (thrd_join(thr, res)) {                                \
		case thrd_success:                                            \
			break;                                                \
		default:                                                      \
			isc_error_fatal(__FILE__, __LINE__,                   \
					"mtx_init failed: Unexpected error"); \
		}                                                             \
	}

#define isc_thread_setconcurrency(level)

#define isc_thread_yield(void) thrd_yield()

#define isc_thread_setname(thread, name)

#define isc_thread_setaffinity(cpu)

#define isc_thread_self (uintptr_t) thrd_current

ISC_LANG_ENDDECLS

#elif _WIN32

typedef HANDLE isc_thread_t;
typedef DWORD  isc_threadresult_t;
typedef void * isc_threadarg_t;
typedef isc_threadresult_t(WINAPI *isc_threadfunc_t)(isc_threadarg_t);

ISC_LANG_BEGINDECLS

void
isc_thread_create(isc_threadfunc_t, isc_threadarg_t, isc_thread_t *);

void
isc_thread_join(isc_thread_t, isc_threadresult_t *);

#define isc_thread_setconcurrency(level)

#define isc_thread_yield() Sleep(0)

#define isc_thread_setname(thread, name)

#define isc_thread_setaffinity(cpu)

#define isc_thread_self (unsigned long)GetCurrentThreadId

#endif
