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
#include <isc/mem.h>

typedef struct isc_faaa_queue isc_faaa_queue_t;

isc_faaa_queue_t *
isc_faaa_queue_new(isc_mem_t *mctx, int max_threads);

uintptr_t
isc_faaa_queue_dequeue(isc_faaa_queue_t *queue);

void
isc_faaa_queue_enqueue(isc_faaa_queue_t *queue, uintptr_t item);

void
isc_faaa_queue_destroy(isc_faaa_queue_t *queue);
