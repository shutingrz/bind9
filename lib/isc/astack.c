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

#include <inttypes.h>
#include <string.h>

#include <isc/astack.h>
#include <isc/atomic.h>
#include <isc/mem.h>
#include <isc/types.h>
#include <isc/util.h>

struct isc_astack {
	isc_mem_t *mctx;
	size_t size;
	atomic_uint_fast32_t current;
	_Atomic uintptr_t nodes[];
};

isc_astack_t *
isc_astack_new(isc_mem_t *mctx, size_t size) {
	isc_astack_t *stack =
		isc_mem_get(mctx,
			    sizeof(isc_astack_t) + size * sizeof(uintptr_t));

	stack->mctx = NULL;
	isc_mem_attach(mctx, &stack->mctx);
	stack->size = size;
	atomic_init(&stack->current, 0);
	memset(stack->nodes, 0, size * sizeof(uintptr_t));
	return (stack);
}

bool
isc_astack_trypush(isc_astack_t *stack, void *obj) {
	atomic_uint_fast32_t cur = atomic_load(&stack->current);
	uintptr_t v = 0;

	if (cur >= stack->size) {
		return (false);
	}

	/* We first add the value to the list */
	if (atomic_compare_exchange_strong(&stack->nodes[cur], &v,
					   (uintptr_t) obj))
	{
		/* Success, we can update cur */
		atomic_fetch_add(&stack->current, 1);
		return (true);
	} else {
		/* Failure, bail */
		return (false);
	}
}

void *
isc_astack_pop(isc_astack_t *stack) {
	uintptr_t nv = 0;

	while (true) {
		uint_fast32_t cur = atomic_load(&stack->current);
		uint_fast32_t next;

		if (cur == 0) {
			return (NULL);
		}

		next = cur - 1;

		if (atomic_compare_exchange_strong(&stack->current,
						   &cur, next))
		{
			void *obj =
				(void *) atomic_exchange(&stack->nodes[next],
							 nv);
			return (obj);
		}
	}
}

void
isc_astack_destroy(isc_astack_t *stack) {
	REQUIRE(stack->current == 0);

	isc_mem_putanddetach(&stack->mctx, stack,
			     sizeof(struct isc_astack) +
			      stack->size * sizeof(uintptr_t));
}
