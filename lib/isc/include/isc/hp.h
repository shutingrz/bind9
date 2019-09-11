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
/*
 * This work is based on C++ code available from:
 * https://github.com/pramalhe/ConcurrencyFreaks/
 *
 * Copyright (c) 2014-2016, Pedro Ramalhete, Andreia Correia
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Concurrency Freaks nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************
 */

#include <isc/atomic.h>
#include <isc/string.h>
#include <isc/mem.h>
#include <isc/util.h>

typedef void
(isc_hp_deletefunc_t)(void *);

typedef struct isc_hp isc_hp_t;

isc_hp_t *
isc_hp_new(isc_mem_t *mctx, size_t max_hps, size_t max_threads, isc_hp_deletefunc_t *deletefunc);

void
isc_hp_destroy(isc_hp_t *hp);

void
isc_hp_clear(isc_hp_t *hp, const int tid);

void isc_hp_clear_one(isc_hp_t *hp, int ihp, const int tid);

uintptr_t
isc_hp_protect(isc_hp_t *hp, int ihp, const atomic_uintptr_t atom, const int tid);

uintptr_t
isc_hp_protect_ptr(isc_hp_t *hp, int ihp, const atomic_uintptr_t ptr, const int tid);

uintptr_t
isc_hp_protect_release(isc_hp_t *hp, int ihp, const atomic_uintptr_t ptr, const int tid);

void
isc_hp_retire(isc_hp_t *hp, const atomic_uintptr_t ptr, const int tid);
