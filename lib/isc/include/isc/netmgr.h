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

#include <config.h>

#include <isc/mem.h>
#include <isc/result.h>
#include <isc/types.h>

typedef enum {
	NMEV_READ,
	NMEV_WRITE,
	NMEV_ACCEPT,
	NMEV_CONNECTED,
	NMEV_CANCELLED,
	NMEV_SHUTDOWN
} isc_nm_eventtype;

/*
 * isc_nm_start creates and starts a netmgr
 */
isc_nm_t *
isc_nm_start(isc_mem_t *mctx, uint32_t workers);

/*
 * isc_nm_shutdown shutdowns netmgr, freeing all the resources
 */
void
isc_nm_shutdown(isc_nm_t **mgr);

void
isc_nm_attach(isc_nm_t *mgr, isc_nm_t **dst);

void
isc_nm_detach(isc_nm_t **mgr0);

/* Return thread id of current thread, or ISC_NETMGR_TID_UNKNOWN */
int
isc_nm_tid(void);

/*
 * isc_nm_freehandle frees a handle, releasing resources
 */
void
isc_nm_freehandle(isc_nmhandle_t *handle);

void
isc_nmsocket_attach(isc_nmsocket_t *socket, isc_nmsocket_t **target);
/*%<
 * isc_nmsocket_attach attaches to a socket, increasing refcount
 */

void
isc_nmsocket_close(isc_nmsocket_t *socket);

void
isc_nmsocket_detach(isc_nmsocket_t **socketp);
/*%<
 * isc_nmsocket_detach detaches from socket, decreasing refcount
 * and possibly destroying the socket if it's no longer referenced.
 */

void
isc_nmhandle_attach(isc_nmhandle_t *handle, isc_nmhandle_t **handlep);

void
isc_nmhandle_detach(isc_nmhandle_t **handlep);

void *
isc_nmhandle_getdata(isc_nmhandle_t *handle);

void *
isc_nmhandle_getextra(isc_nmhandle_t *handle);

typedef void (*isc_nm_opaquecb)(void *arg);

bool
isc_nmhandle_is_stream(isc_nmhandle_t *handle);

/*
 * isc_nmhandle_t has a void * opaque field (usually - ns_client_t).
 * We reuse handle and `opaque` can also be reused between calls.
 * This function sets this field and two callbacks:
 * - doreset resets the `opaque` to initial state
 * - dofree frees everything associated with `opaque`
 */
void
isc_nmhandle_setdata(isc_nmhandle_t *handle, void *arg,
		     isc_nm_opaquecb doreset, isc_nm_opaquecb dofree);

isc_sockaddr_t
isc_nmhandle_peeraddr(isc_nmhandle_t *handle);

/*
 * Callback for receiving a packet.
 * arg is the argument passed to isc_nm_listen_udp
 * handle - handle that can be used to send back the answer
 * region - contains the received data. It will be freed after
 *          return by caller
 */
typedef void (*isc_nm_recv_cb_t)(void *arg, isc_nmhandle_t *handle,
				 isc_region_t *region);

/*
 * isc_nm_udp_listen starts listening for UDP packets on iface using mgr.
 * When a packet is received cb is called with cbarg as its first argument
 */
isc_result_t
isc_nm_listenudp(isc_nm_t *mgr, isc_nmiface_t *iface,
		 isc_nm_recv_cb_t cb, void *cbarg,
		 size_t extrasize, isc_nmsocket_t **rv);

void
isc_nm_udp_stoplistening(isc_nmsocket_t *socket);


/* XXXWPK TODOs */
typedef void (*isc_nm_send_cb_t)(isc_nmhandle_t *handle, isc_result_t result,
				 void *cbarg);
typedef void (*isc_nm_connect_cb_t)(isc_nmhandle_t *handle,
				    isc_result_t result, void *cbarg);
typedef void (*isc_nm_accept_cb_t)(isc_nmhandle_t *handle, isc_result_t result,
				   void *cbarg);

/*
 * isc_nm_pause pauses all processing, equivalent to taskmgr exclusive tasks.
 * It won't return until all workers are paused.
 */
void
isc_nm_pause(isc_nm_t *mgr);

/*
 * isc_nm_resume resumes paused processing. It will return immediately
 * after signalling workers to resume.
 */
void
isc_nm_resume(isc_nm_t *mgr);

isc_result_t
isc_nm_tcp_connect(isc_nm_t *mgr, isc_nmiface_t *iface, isc_sockaddr_t *peer,
		   isc_nm_connect_cb_t cb, void *cbarg);

isc_nmsocket_t *
isc_nm_udp_socket();

isc_result_t
isc_nm_dnsread(isc_nmsocket_t *socket, isc_buffer_t *buf);


isc_result_t
isc_nm_read(isc_nmhandle_t *handle, isc_nm_recv_cb_t cb, void *cbarg);

isc_result_t
isc_nm_pauseread(isc_nmsocket_t *socket);
/*%<
 * Pause reading on this socket, while still remembering the callback.
 */

isc_result_t
isc_nm_resumeread(isc_nmsocket_t *socket);
/*%<
 * Resume reading from socket, the socket read had to be paused beforehand.
 */

isc_result_t
isc_nm_send(isc_nmhandle_t *handle, isc_region_t *region,
	    isc_nm_send_cb_t cb, void *cbarg);
/*%<
 * Send the data in 'region' via 'handle'. Afterward, the callback 'cb' is
 * called with the argument 'cbarg'.
 *
 * 'region' is not copied; it has to be allocated beforehand and freed
 * in 'cb'.
 *
 * Callback can be invoked directly from the calling thread, or called later.
 */

isc_result_t
isc_nm_listentcp(isc_nm_t *mgr, isc_nmiface_t *iface,
		 isc_nm_accept_cb_t cb, void *cbarg,
		 size_t extrahandlesize, isc_quota_t *quota,
		 isc_nmsocket_t **rv);

void
isc_nm_tcp_stoplistening(isc_nmsocket_t *socket);

isc_result_t
isc_nm_listentcpdns(isc_nm_t *mgr, isc_nmiface_t *iface,
		     isc_nm_recv_cb_t cb, void *arg,
		     size_t extrahandlesize, isc_quota_t *quota,
		     isc_nmsocket_t **rv);

void
isc_nm_tcpdns_stoplistening(isc_nmsocket_t *socket);

void
isc_nm_tcpdns_sequential(isc_nmhandle_t *handle);
/*%<
 * Disable pipelining on this connection. Each DNS packet
 * will be only processed after the previous completes.
 *
 * This cannot be reversed once set for a given connection
 */
