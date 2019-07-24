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

#include "config.h"

#include <unistd.h>
#include <uv.h>
#include <ck_fifo.h>
#include <ck_stack.h>

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


/*
 * Single network event loop worker.
 */
typedef struct isc__networker {
	isc_nm_t *		   mgr;
	int			   id;          /* thread id */
	uv_loop_t		   loop;        /* libuv loop structure */
	uv_async_t		   async;       /* async channel to send
	                                         * data to this networker */
	isc_mutex_t		   lock;
	isc_mempool_t *		   mpool_bufs;
	isc_condition_t		   cond;
	bool			   paused;
	bool			   finished;
	isc_thread_t		   thread;
	struct ck_fifo_mpmc	   ievents;     /* incoming async events */
	isc_refcount_t		   references;
	atomic_int_fast64_t	   pktcount;
	char			   udprecvbuf[65536];
	bool			   udprecvbuf_inuse;
} isc__networker_t;

/*
 * A general handle for a connection bound to a networker.
 * For UDP connections we have peer address here,
 * so both TCP and UDP can be handled with a simple send-like
 * function
 */
#define NMHANDLE_MAGIC                        ISC_MAGIC('N', 'M', 'H', 'D')
#define VALID_NMHANDLE(t)                     ISC_MAGIC_VALID(t, \
							      NMHANDLE_MAGIC)

struct isc_nmhandle {
	int			magic;
	isc_refcount_t		refs;
	isc_nmsocket_t *	socket;
	isc_sockaddr_t		peer;
	void *			opaque;
	ck_stack_entry_t	ilink;
	isc_nm_opaquecb		doreset;
	isc_nm_opaquecb		dofree;
	char			extra[];
};

CK_STACK_CONTAINER(struct isc_nmhandle, ilink, nm_handle_is_get)

/*
 * An interface - an address we can listen on.
 */
struct isc_nmiface {
	isc_sockaddr_t        addr;
};

typedef enum isc__netievent_type {
	netievent_stop,
	netievent_udplisten,
	netievent_udpstoplisten,
	netievent_udpsend,
	netievent_udprecv,
	netievent_tcpconnect,
	netievent_tcpsend,
	netievent_tcprecv,
	netievent_tcpstartread,
	netievent_tcpstopread,
	netievent_tcplisten,
	netievent_tcpstoplisten,
} isc__netievent_type;

typedef struct isc__netievent_stop {
	isc__netievent_type        type;
} isc__netievent_stop_t;

/* We have to split it because we can read and write on a socket simultaneously */
typedef union {
	isc_nm_recv_cb_t	   recv;
	isc_nm_accept_cb_t	   accept;
} isc__nm_readcb_t;

typedef union {
	isc_nm_send_cb_t	   send;
	isc_nm_connect_cb_t	   connect;
} isc__nm_writecb_t;

typedef union {
	isc_nm_recv_cb_t	   recv;
	isc_nm_accept_cb_t	   accept;
	isc_nm_send_cb_t	   send;
	isc_nm_connect_cb_t	   connect;
} isc__nm_cb_t;

/*
 * Wrapper around uv_req_t with 'our' fields in it.
 * req->data should always point to it's parent.
 * Note that we always allocate more than sizeof(struct)
 * because we make room for different req types;
 */
#define UVREQ_MAGIC                        ISC_MAGIC('N', 'M', 'U', 'R')
#define VALID_UVREQ(t)                     ISC_MAGIC_VALID(t, UVREQ_MAGIC)

typedef struct isc__nm_uvreq {
	int		      magic;
	isc_nm_t *	      mgr;
	uv_buf_t	      uvbuf; /* translated isc_region_t, to be sent or
	                              * received */
	isc_sockaddr_t	      local; /* local address */
	isc_sockaddr_t	      peer;  /* peer address */
	isc__nm_cb_t 	      cb;    /* callback */
	void *		      cbarg;
	isc_nmhandle_t *      handle;
	ck_stack_entry_t      ilink;
	union {
		uv_req_t		req;
		uv_getaddrinfo_t	getaddrinfo;
		uv_getnameinfo_t	getnameinfo;
		uv_shutdown_t		shutdown;
		uv_write_t		write;
		uv_connect_t		connect;
		uv_udp_send_t		udp_send;
		uv_fs_t			fs;
		uv_work_t		work;
	} uv_req;
} isc__nm_uvreq_t;

CK_STACK_CONTAINER(struct isc__nm_uvreq, ilink, uvreq_is_get);

/*
 * Make the worker listen for UDP requests on a specified socket.
 * socket must have FD and iface filled.
 */

typedef struct isc__netievent_udplisten {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
} isc__netievent_udplisten_t;

typedef struct isc__netievent_udpstoplisten {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
} isc__netievent_udpstoplisten_t;

typedef struct isc__netievent_udpsend {
	isc__netievent_type	   type;
	isc_nmhandle_t		   handle;
	isc__nm_uvreq_t *	   req;
} isc__netievent_udpsend_t;

typedef struct isc__netievent_tcpconnect {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
	isc__nm_uvreq_t *	   req;
} isc__netievent_tcpconnect_t;

typedef struct isc__netievent_tcplisten {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
	isc__nm_uvreq_t *	   req;
} isc__netievent_tcplisten_t;

typedef struct isc__netievent_tcpsend {
	isc__netievent_type	   type;
	isc_nmhandle_t		   handle;
	isc__nm_uvreq_t *	   req;
} isc__netievent_tcpsend_t;

typedef struct isc__netievent_startread {
	isc__netievent_type	   type;
	isc_nmsocket_t *	   socket;
	isc__nm_uvreq_t *	   req;
} isc__netievent_startread_t;

typedef struct isc__netievent {
	isc__netievent_type        type;
} isc__netievent_t;

typedef struct isc__netievent_storage {
	union {
		isc__netievent_t		  ni;
		isc__netievent_stop_t		  nis;
		isc__netievent_udplisten_t	  niul;
		isc__netievent_udpsend_t	  nius;
	};
} isc__netievent_storage_t;

/*
 * Network manager
 */
#define NM_MAGIC                        ISC_MAGIC('N', 'E', 'T', 'M')
#define VALID_NM(t)                     ISC_MAGIC_VALID(t, NM_MAGIC)

struct isc_nm {
	int			    magic;
	isc_refcount_t		    refs;
	isc_mem_t *		    mctx;
	int			    nworkers;
	isc_mutex_t		    lock;
	isc_condition_t		    wkstatecond;
	isc__networker_t *	    workers;
	atomic_uint_fast32_t	    workers_running;
	atomic_uint_fast32_t	    workers_paused;
};


typedef enum isc_nmsocket_type {
	isc_nm_udpsocket,
	isc_nm_udplistener, /* Aggregate of nm_udpsocks */
	isc_nm_tcpsocket,
	isc_nm_tcplistener,
	isc_nm_tcpdnslistener,
	isc_nm_tcpdnssocket
} isc_nmsocket_type;


/*
 * An universal structure for either a single socket or
 * a group of dup'd/SO_REUSE_PORT-using sockets listening
 * on the same interface.
 */
#define NMSOCK_MAGIC                    ISC_MAGIC('N', 'M', 'S', 'K')
#define VALID_NMSOCK(t)                 ISC_MAGIC_VALID(t, NMSOCK_MAGIC)
struct isc_nmsocket {
	int				  magic;
	isc_nmsocket_type		  type;
	isc_refcount_t			  refs;
	isc_nm_t *			  mgr;
	isc_nmsocket_t *		  parent;
	isc_nmsocket_t *		  children;
	int				  nchildren;
	atomic_int_fast32_t		  rchildren;
	int				  tid;
	isc_nmiface_t *			  iface;
	isc_nmhandle_t			  tcphandle;
	/*
	 * 'spare' handles for that can be reused to avoid allocations,
	 * for UDP.
	 */
	ck_stack_t inactivehandles	  CK_CC_CACHELINE;
	ck_stack_t inactivereqs		  CK_CC_CACHELINE;
	/* extra data allocated at the end of each isc_nmhandle_t */
	size_t				  extrahandlesize;

	uv_os_sock_t			  fd;
	union {
		uv_handle_t	   handle;
		uv_stream_t	   stream;
		uv_udp_t	   udp;
		uv_tcp_t	   tcp;
	} uv_handle;

	isc__nm_readcb_t	    rcb;
	void *		 	    rcbarg;
	isc__nm_writecb_t	    wcb;
	void *			    wcbarg;
};

static void *
isc__net_thread(void *worker0);
static void
async_cb(uv_async_t *handle);
static void *
get_ievent(isc_nm_t *mgr, isc__netievent_type type);
static void
enqueue_ievent(isc__networker_t *worker, isc__netievent_t *event);
static void
alloc_cb(uv_handle_t *handle, size_t size, uv_buf_t *buf);
static void
free_uvbuf(isc_nmsocket_t *socket, const uv_buf_t *buf);
static isc_nmhandle_t *
alloc_handle(isc_nmsocket_t *socket);
static isc_nmhandle_t *
get_handle(isc_nmsocket_t *socket, isc_sockaddr_t *peer);
static isc__nm_uvreq_t *
isc__nm_uvreq_get(isc_nm_t *mgr, isc_nmsocket_t *socket);
static void
isc__nm_uvreq_put(isc__nm_uvreq_t **req, isc_nmsocket_t *socket);

static isc_result_t
isc__nm_udp_send_direct(isc_nmsocket_t *socket,
			isc__nm_uvreq_t *req,
			isc_sockaddr_t *peer);
static isc_result_t
isc__nm_udp_send(isc_nmhandle_t *handle,
		 isc_region_t *region,
		 isc_nm_send_cb_t cb,
		 void *cbarg);
static void
udp_recv_cb(uv_udp_t *handle,
	    ssize_t nrecv,
	    const uv_buf_t *buf,
	    const struct sockaddr *addr,
	    unsigned flags);
static void
handle_udplisten(isc__networker_t *worker, isc__netievent_t *ievent0);

static void
handle_udpstoplisten(isc__networker_t *worker, isc__netievent_t *ievent0);

static void
handle_udpsend(isc__networker_t *worker, isc__netievent_t *ievent0);

static void
udp_send_cb(uv_udp_send_t *req, int status);

static int
isc__nm_tcp_connect_direct(isc_nmsocket_t *socket, isc__nm_uvreq_t *req);

static isc_result_t
isc__nm_tcp_send(isc_nmhandle_t *handle,
		 isc_region_t *region,
		 isc_nm_send_cb_t cb,
		 void *cbarg);

static isc_result_t
isc__nm_tcp_send_direct(isc_nmsocket_t *socket,
			isc__nm_uvreq_t *req);



static void
handle_tcpconnect(isc__networker_t *worker, isc__netievent_t *ievent0);
static void
tcp_connect_cb(uv_connect_t *uvreq, int status);

static void
handle_tcplisten(isc__networker_t *worker, isc__netievent_t *ievent0);
static void
handle_tcpsend(isc__networker_t *worker, isc__netievent_t *ievent0);
static void
tcp_connection_cb(uv_stream_t *server, int status);

static void
handle_startread(isc__networker_t *worker, isc__netievent_t *ievent0);
/* static void
handle_stopread(isc__networker_t *worker, isc__netievent_t *ievent0);
*/
static void
read_cb(uv_stream_t* stream,
        ssize_t nread,
        const uv_buf_t* buf);


static void
dnslisten_readcb(void *arg, isc_nmhandle_t* handle, isc_region_t *region);

static isc_result_t
isc__nm_tcpdns_send(isc_nmhandle_t *handle,
		    isc_region_t *region,
		    isc_nm_send_cb_t cb,
		    void *cbarg);