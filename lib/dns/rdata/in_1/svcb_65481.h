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

#ifndef IN_1_SVCB_65481_H
#define IN_1_SVCB_65481_H 1

/*!
 *  \brief Per draft-ietf-dnsop-svcb-httpssvc-02
 */

typedef struct dns_rdata_in_svcb {
	dns_rdatacommon_t common;
	isc_mem_t *mctx;
	uint16_t priority;
	dns_name_t svcdomain;
	uint16_t svclen;
	unsigned char *svc;
} dns_rdata_in_svcb_t;

#endif /* IN_1_SVCB_65481_H */
