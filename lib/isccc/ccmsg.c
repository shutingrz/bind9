/*
 * Portions Copyright (C) Internet Systems Consortium, Inc. ("ISC")
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * See the COPYRIGHT file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * Portions Copyright (C) 2001 Nominum, Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC AND NOMINUM DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*! \file */

#include <inttypes.h>

#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/result.h>
#include <isc/string.h>
#include <isc/util.h>

#include <isccc/ccmsg.h>
#include <isccc/events.h>

#define CCMSG_MAGIC	 ISC_MAGIC('C', 'C', 'm', 's')
#define VALID_CCMSG(foo) ISC_MAGIC_VALID(foo, CCMSG_MAGIC)

static void
recv_message(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	     void *arg);

static void
recv_nonce(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	   void *arg) {
	isccc_ccmsg_t *ccmsg = arg;
	isc_result_t result;

	INSIST(VALID_CCMSG(ccmsg));

	if (region == NULL && eresult == ISC_R_SUCCESS) {
		ccmsg->result = ISC_R_EOF;
		goto done;
	} else if (eresult != ISC_R_SUCCESS) {
		ccmsg->result = eresult;
		goto done;
	} else {
		ccmsg->result = eresult;
	}

	if (region->length < sizeof(uint32_t)) {
		ccmsg->result = ISC_R_UNEXPECTEDEND;
		goto done;
	}

	ccmsg->size = ntohl(*(uint32_t *)region->base);
	if (ccmsg->size == 0) {
		ccmsg->result = ISC_R_UNEXPECTEDEND;
		goto done;
	}
	if (ccmsg->size > ccmsg->maxsize) {
		ccmsg->result = ISC_R_RANGE;
		goto done;
	}

	isc_region_consume(region, sizeof(uint32_t));
	isc_buffer_allocate(ccmsg->mctx, &ccmsg->buffer, ccmsg->size);

	/*
	 * If there's more of the message waiting, pass it to
	 * recv_message() directly.
	 */
	if (region->length != 0) {
		recv_message(handle, ISC_R_SUCCESS, region, ccmsg);
		return;
	}

	/*
	 * Otherwise, continue reading and handle it in
	 * recv_message().
	 */
	result = isc_nm_read(handle, recv_message, ccmsg);
	if (result == ISC_R_SUCCESS) {
		return;
	}

	ccmsg->result = result;

done:
	ccmsg->cb(handle, ccmsg->result, ccmsg->cbarg);
}

static void
recv_message(isc_nmhandle_t *handle, isc_result_t eresult, isc_region_t *region,
	     void *arg) {
	isc_result_t result;
	isccc_ccmsg_t *ccmsg = arg;
	size_t size;

	INSIST(VALID_CCMSG(ccmsg));

	if (region == NULL && eresult == ISC_R_SUCCESS) {
		ccmsg->result = ISC_R_EOF;
		goto done;
	} else if (eresult != ISC_R_SUCCESS) {
		ccmsg->result = eresult;
		goto done;
	} else {
		ccmsg->result = eresult;
	}

	if (region->length == 0) {
		ccmsg->result = ISC_R_UNEXPECTEDEND;
		goto done;
	}

	size = ISC_MIN(isc_buffer_availablelength(ccmsg->buffer),
		       region->length);
	isc_buffer_putmem(ccmsg->buffer, region->base, size);
	isc_region_consume(region, size);

	if (isc_buffer_usedlength(ccmsg->buffer) == ccmsg->size) {
		ccmsg->result = ISC_R_SUCCESS;
		goto done;
	}

	result = isc_nm_read(handle, recv_message, ccmsg);
	if (result == ISC_R_SUCCESS) {
		return;
	}

	ccmsg->result = result;

done:
	ccmsg->cb(handle, ccmsg->result, ccmsg->cbarg);
}

void
isccc_ccmsg_init(isc_mem_t *mctx, isc_nmhandle_t *handle,
		 isccc_ccmsg_t *ccmsg) {
	REQUIRE(mctx != NULL);
	REQUIRE(handle != NULL);
	REQUIRE(ccmsg != NULL);

	*ccmsg = (isccc_ccmsg_t){
		.magic = CCMSG_MAGIC,
		.maxsize = 0xffffffffU, /* Largest message possible. */
		.mctx = mctx,
		.handle = handle,
		.result = ISC_R_UNEXPECTED /* None yet. */
	};
}

void
isccc_ccmsg_setmaxsize(isccc_ccmsg_t *ccmsg, unsigned int maxsize) {
	REQUIRE(VALID_CCMSG(ccmsg));

	ccmsg->maxsize = maxsize;
}

isc_result_t
isccc_ccmsg_readmessage(isccc_ccmsg_t *ccmsg, isc_nm_cb_t cb, void *cbarg) {
	isc_result_t result;

	REQUIRE(VALID_CCMSG(ccmsg));

	if (ccmsg->buffer != NULL) {
		isc_buffer_free(&ccmsg->buffer);
	}

	ccmsg->cb = cb;
	ccmsg->cbarg = cbarg;
	ccmsg->result = ISC_R_UNEXPECTED; /* unknown right now */

	result = isc_nm_read(ccmsg->handle, recv_nonce, ccmsg);

	return (result);
}

void
isccc_ccmsg_cancelread(isccc_ccmsg_t *ccmsg) {
	REQUIRE(VALID_CCMSG(ccmsg));

#if 0
	/* XXX: not sure if this is needed with the netmgr */
	isc_socket_cancel(ccmsg->sock, NULL, ISC_SOCKCANCEL_RECV);
#endif
}

void
isccc_ccmsg_invalidate(isccc_ccmsg_t *ccmsg) {
	REQUIRE(VALID_CCMSG(ccmsg));

	ccmsg->magic = 0;

	if (ccmsg->buffer != NULL) {
		isc_buffer_free(&ccmsg->buffer);
	}
}
