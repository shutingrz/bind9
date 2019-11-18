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


#ifndef ISC_MAGIC_H
#define ISC_MAGIC_H 1

#include <isc/atomic.h>
#include <isc/likely.h>

/*! \file isc/magic.h */

typedef atomic_uint_fast32_t isc_magic_t;

typedef struct {
	isc_magic_t magic;
} isc__magic_t;

/*%
 * To use this macro the magic number MUST be the first thing in the
 * structure, and MUST be of type "unsigned int".
 * The intent of this is to allow magic numbers to be checked even though
 * the object is otherwise opaque.
 */

#define ISC_MAGIC_VALID(o, v)						\
	(ISC_LIKELY((o) != NULL) &&					\
	 ISC_LIKELY(atomic_load_acquire(&((const isc__magic_t *)(o))->magic) == (v)))

#define ISC_MAGIC(a, b, c, d)	((a) << 24 | (b) << 16 | (c) << 8 | (d))

#define ISC_MAGIC_INIT(o, v) atomic_init(&(o)->magic, (v))

#define ISC_MAGIC_CLEAR(o) atomic_store_release(&(o)->magic, 0)

#define ISC_IMPMAGIC_INIT(o, v) atomic_init(&(o)->impmagic, (v))

#define ISC_IMPMAGIC_CLEAR(o) atomic_store_release(&(o)->impmagic, 0)

#endif /* ISC_MAGIC_H */
