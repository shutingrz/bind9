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

#ifndef DST_RESULT_H
#define DST_RESULT_H 1

/*! \file dst/result.h */

#include <isc/lang.h>
#include <isc/resultclass.h>

#define DST_R_UNSUPPORTEDALG ISC_RESULTCODE_DST(0)
#define DST_R_CRYPTOFAILURE  ISC_RESULTCODE_DST(1)
/* compat */
#define DST_R_OPENSSLFAILURE	DST_R_CRYPTOFAILURE
#define DST_R_NOCRYPTO		ISC_RESULTCODE_DST(2)
#define DST_R_NULLKEY		ISC_RESULTCODE_DST(3)
#define DST_R_INVALIDPUBLICKEY	ISC_RESULTCODE_DST(4)
#define DST_R_INVALIDPRIVATEKEY ISC_RESULTCODE_DST(5)
/* 6 is unused */
#define DST_R_WRITEERROR   ISC_RESULTCODE_DST(7)
#define DST_R_INVALIDPARAM ISC_RESULTCODE_DST(8)
/* 9 is unused */
/* 10 is unused */
#define DST_R_SIGNFAILURE ISC_RESULTCODE_DST(11)
/* 12 is unused */
/* 13 is unused */
#define DST_R_VERIFYFAILURE	     ISC_RESULTCODE_DST(14)
#define DST_R_NOTPUBLICKEY	     ISC_RESULTCODE_DST(15)
#define DST_R_NOTPRIVATEKEY	     ISC_RESULTCODE_DST(16)
#define DST_R_KEYCANNOTCOMPUTESECRET ISC_RESULTCODE_DST(17)
#define DST_R_COMPUTESECRETFAILURE   ISC_RESULTCODE_DST(18)
#define DST_R_NORANDOMNESS	     ISC_RESULTCODE_DST(19)
#define DST_R_BADKEYTYPE	     ISC_RESULTCODE_DST(20)
#define DST_R_NOENGINE		     ISC_RESULTCODE_DST(21)
#define DST_R_EXTERNALKEY	     ISC_RESULTCODE_DST(22)

#define DST_R_NRESULTS 23 /* Number of results */

#endif /* DST_RESULT_H */
