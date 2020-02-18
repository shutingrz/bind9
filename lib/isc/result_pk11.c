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

#include <stddef.h>

#include <pk11/result.h>

static const char *pk11_result_descriptions[PK11_R_NRESULTS] = {
	"PKCS#11 initialization failed", /*%< 0 */
	"no PKCS#11 provider",		 /*%< 1 */
	"PKCS#11 no random service",	 /*%< 2 */
	"PKCS#11 no digist service",	 /*%< 3 */
	"PKCS#11 no AES service",	 /*%< 4 */
};

static const char *pk11_result_ids[PK11_R_NRESULTS] = {
	"PK11_R_INITFAILED",	  /* 0 */
	"PK11_R_NOPROVIDER",	  /* 1 */
	"PK11_R_NORANDOMSERVICE", /* 2 */
	"PK11_R_NODIGESTSERVICE", /* 3 */
	"PK11_R_NOAESSERVICE",	  /* 4 */
};
