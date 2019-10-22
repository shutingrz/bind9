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

#include <unistd.h>
#include <uv.h>

#include <isc/atomic.h>
#include <isc/buffer.h>
#include <isc/condition.h>
#include <isc/magic.h>
#include <isc/mem.h>
#include <isc/netmgr.h>
#include <isc/random.h>
#include <isc/refcount.h>
#include <isc/region.h>
#include <isc/result.h>
#include <isc/sockaddr.h>
#include <isc/thread.h>
#include <isc/util.h>

#include "netmgr-int.h"

static inline size_t
dnslen(unsigned char* base) {
	return ((base[0] << 8) + (base[1]));
}

#define NM_REG_BUF 4096
#define NM_BIG_BUF 65536
static inline void
alloc_dnsbuf(isc_nmsocket_t *sock, size_t len) {
	REQUIRE(len <= NM_BIG_BUF);
	if (sock->buf == NULL) {
		/* We don't have the buffer at all */
		size_t alloc_len = len < NM_REG_BUF ? NM_REG_BUF : NM_BIG_BUF;
		sock->buf = isc_mem_get(sock->mgr->mctx, alloc_len);
		sock->buf_size = alloc_len;
	} else {
		/* We have the buffer but it's too small */
		sock->buf = isc_mem_reallocate(sock->mgr->mctx,
					       sock->buf,
					       NM_BIG_BUF);
		sock->buf_size = NM_BIG_BUF;
	}
}


static void
dnslisten_readcb(void *arg, isc_nmhandle_t *handle, isc_region_t *region);

/*
 * Accept callback for TCP-DNS connection
 */
static void
dnslisten_acceptcb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	isc_nmsocket_t *dnslistensocket = (isc_nmsocket_t *) cbarg;
	isc_nmsocket_t *dnssocket = NULL;

	REQUIRE(VALID_NMSOCK(dnslistensocket));
	REQUIRE(dnslistensocket->type == isc_nm_tcpdnslistener);

	/* If accept() was unnsuccessful we can't do anything */
	if (result != ISC_R_SUCCESS) {
		return;
	}

	/* We need to create a 'wrapper' dnssocket for this connection */
	dnssocket = isc_mem_get(handle->socket->mgr->mctx, sizeof(*dnssocket));
	isc__nmsocket_init(dnssocket, handle->socket->mgr,
			   isc_nm_tcpdnssocket);

	/* We need to copy read callbacks from outer socket */
	dnssocket->rcb.recv = dnslistensocket->rcb.recv;
	dnssocket->rcbarg = dnslistensocket->rcbarg;
	dnssocket->extrahandlesize = dnslistensocket->extrahandlesize;
	isc_nmsocket_attach(handle->socket, &dnssocket->outer);

	isc_nm_read(handle, dnslisten_readcb, dnssocket);
}

/*
 * We've got a read on our underlying socket, need to check if we have
 * a complete DNS packet and, if so - call the callback
 */
static void
dnslisten_readcb(void *arg, isc_nmhandle_t *handle, isc_region_t *region) {
	isc_nmsocket_t *dnssocket = (isc_nmsocket_t *) arg;

	if (region == NULL) {
		/* Connection closed */
		atomic_store(&dnssocket->closed, true);
		isc_nmsocket_detach(&dnssocket->outer);
		isc_nmsocket_detach(&dnssocket);
		return;
	}

	unsigned char * base = region->base;
	size_t len = region->length;

	/*
	 * We have something in the buffer, we need to glue it.
	 */
	if (dnssocket->buf_len > 0) {
		if (dnssocket->buf_len == 1) {
			/* Make sure we have the length */
			dnssocket->buf[1] = base[0];
			base++;
			len--;
		}
		/* At this point we definitely have 2 bytes there. */
		size_t plen = len < dnslen(dnssocket->buf) ?
			       len : dnslen(dnssocket->buf);
		if (plen > dnssocket->buf_size) {
			alloc_dnsbuf(dnssocket, plen);
		}

		memmove(dnssocket->buf + dnssocket->buf_len, base, plen);
		dnssocket->buf_len += plen;
		base += plen;
		len -= plen;
		/* Do we have a complete packet in the buffer? */
		if (dnslen(dnssocket->buf) == dnssocket->buf_len - 2) {
			isc_region_t r2;
			isc_nmhandle_t *dnshandle;
			r2.base = dnssocket->buf + 2;
			r2.length = dnslen(dnssocket->buf);
			dnshandle = isc__nmhandle_get(dnssocket,
						      &handle->peer);
			dnssocket->rcb.recv(dnssocket->rcbarg,
					    dnshandle,
					    &r2);
			isc_nmhandle_detach(&dnshandle);
		} else {
			/*
			 * If we don't have the whole packet make sure
			 * we copied everything.
			 */
			INSIST(len == 0);
		}
	}

	/*
	 * We don't have anything in buffer, process what's incoming
	 */
	while (len >= 2 && dnslen(base) <= len-2) {
		/* We have a packet, pass it */
		isc_region_t r2;
		r2.base = base + 2;
		r2.length = dnslen(base);
		len -= dnslen(base)+2;
		base += dnslen(base)+2;
		isc_nmhandle_t *dnshandle = isc__nmhandle_get(dnssocket,
							      &handle->peer);
		dnssocket->rcb.recv(dnssocket->rcbarg, dnshandle, &r2);
		isc_nmhandle_detach(&dnshandle);
	}
	/*
	 * Put the remainder in the buffer
	 */
	if (len > 0) {
		if (len > dnssocket->buf_size) {
			alloc_dnsbuf(dnssocket, len);
		}
		INSIST(len <= dnssocket->buf_size);
		memcpy(dnssocket->buf, base, len);
		dnssocket->buf_len = len;
	}

}

/*
 * isc_nm_listentcpdns listens for connections and accepts
 * them immediately, then calls the cb for each incoming DNS packet
 * (with 2-byte length stripped) - just like for UDP packet.
 */
isc_result_t
isc_nm_listentcpdns(isc_nm_t *mgr, isc_nmiface_t *iface,
		    isc_nm_recv_cb_t cb, void *cbarg,
		    size_t extrahandlesize, isc_quota_t *quota,
		    isc_nmsocket_t **rv)
{
	/* A 'wrapper' socket object with outer set to true TCP socket */
	isc_nmsocket_t *dnslistensocket =
		isc_mem_get(mgr->mctx, sizeof(*dnslistensocket));
	isc_result_t result;

	isc__nmsocket_init(dnslistensocket, mgr, isc_nm_tcpdnslistener);
	dnslistensocket->iface = iface;
	dnslistensocket->rcb.recv = cb;
	dnslistensocket->rcbarg = cbarg;
	dnslistensocket->extrahandlesize = extrahandlesize;

	/* We set dnslistensocket->outer to a true listening socket */
	result = isc_nm_listentcp(mgr, iface, dnslisten_acceptcb,
				  dnslistensocket, extrahandlesize,
				  quota, &dnslistensocket->outer);

	dnslistensocket->listening = true;
	*rv = dnslistensocket;
	return (result);
}

void
isc_nm_tcpdns_stoplistening(isc_nmsocket_t *socket) {
	REQUIRE(socket->type == isc_nm_tcpdnslistener);

	isc_nm_tcp_stoplistening(socket->outer);
	atomic_store(&socket->listening, false);
	atomic_store(&socket->closed, true);
	isc_nmsocket_detach(&socket->outer);
}


typedef struct tcpsend {
	isc_mem_t		*mctx;
	isc_nmhandle_t		*handle;
	isc_region_t		region;
	isc_nmhandle_t		*orighandle;
	isc_nm_send_cb_t	cb;
	void 			*cbarg;
} tcpsend_t;

static void
tcpdnssend_cb(isc_nmhandle_t *handle, isc_result_t result, void *cbarg) {
	tcpsend_t *ts = (tcpsend_t *) cbarg;

	UNUSED(handle);

	ts->cb(ts->orighandle, result, ts->cbarg);
	isc_nmhandle_detach(&ts->orighandle);
	isc_mem_put(ts->mctx, ts->region.base, ts->region.length);
	isc_mem_putanddetach(&ts->mctx, ts, sizeof(*ts));
}
/*
 * isc__nm_tcp_send sends buf to a peer on a socket.
 */
isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle, isc_region_t *region,
		    isc_nm_send_cb_t cb, void *cbarg)
{
	isc_nmsocket_t *socket = handle->socket;
	tcpsend_t *t = isc_mem_get(socket->mgr->mctx, sizeof(*t));

	REQUIRE(socket->type == isc_nm_tcpdnssocket);

	*t = (tcpsend_t) {};

	isc_mem_attach(socket->mgr->mctx, &t->mctx);
	t->handle = handle->socket->outer->tcphandle;
	t->cb = cb;
	t->cbarg = cbarg;

	t->region = (isc_region_t) {
		.base = isc_mem_get(t->mctx, region->length + 2),
		.length = region->length + 2
	};
	memmove(t->region.base + 2, region->base, region->length);
	t->region.base[0] = (uint8_t) (region->length >> 8);
	t->region.base[1] = (uint8_t) (region->length & 0xff);

	isc_nmhandle_attach(handle, &t->orighandle);

	return (isc__nm_tcp_send(t->handle, &t->region, tcpdnssend_cb, t));
}

void
isc__nm_tcpdns_close(isc_nmsocket_t *socket) {
	isc_nmsocket_detach(&socket->outer);
	socket->closed = true;
	isc__nmsocket_prep_destroy(socket);
}
