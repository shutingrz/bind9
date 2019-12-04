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

#include <isc/platform.h>
#include <isc/result.h>

#if HAVE_PTHREAD

#include <pthread.h>

typedef pthread_once_t isc_once_t;

#define ISC_ONCE_INIT PTHREAD_ONCE_INIT

#define isc_once_do(op, f) \
	((pthread_once((op), (f)) == 0) ? ISC_R_SUCCESS : ISC_R_UNEXPECTED)

#elif HAVE_C11_THREAD_SUPPORT

#include <threads.h>

typedef once_flag isc_once_t;

#define ISC_ONCE_INIT ONCE_FLAG_INIT

#define isc_once_do(flag, func) (call_once((flag), (func)), ISC_R_SUCCESS)

#elif _WIN32

#include <synchapi.h>

typedef PINIT_ONCE isc_once_t;

#define isc_once_do(flag, func)                             \
	((InitOnceExecuteOnce(flag, func, NULL, NULL) != 0) \
		 ? ISC_R_SUCCESS                            \
		 : ISC_R_UNEXPECTED)

#endif /* ISC_ONCE_H */
