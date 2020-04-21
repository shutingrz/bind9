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

/* draft-ietf-dnsop-svcb-httpssvc-02 */

#ifndef RDATA_IN_1_HTTPSSVC_65482_C
#define RDATA_IN_1_HTTPSSVC_65482_C

#define RRTYPE_HTTPSSVC_ATTRIBUTES (0)

static inline isc_result_t
fromtext_in_httpssvc(ARGS_FROMTEXT) {
	REQUIRE(type == dns_rdatatype_httpssvc);
	REQUIRE(rdclass == dns_rdataclass_in);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	return (generic_fromtext_in_svcb(CALL_FROMTEXT));
}

static inline isc_result_t
totext_in_httpssvc(ARGS_TOTEXT) {
	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	return (generic_totext_in_svcb(CALL_TOTEXT));
}

static inline isc_result_t
fromwire_in_httpssvc(ARGS_FROMWIRE) {
	REQUIRE(type == dns_rdatatype_httpssvc);
	REQUIRE(rdclass == dns_rdataclass_in);

	return (generic_fromwire_in_svcb(CALL_FROMWIRE));
}

static inline isc_result_t
towire_in_httpssvc(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->length != 0);

	return (generic_towire_in_svcb(CALL_TOWIRE));
}

static inline int
compare_in_httpssvc(ARGS_COMPARE) {
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata1->rdclass == dns_rdataclass_in);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	return (isc_region_compare(&region1, &region2));
}

static inline isc_result_t
fromstruct_in_httpssvc(ARGS_FROMSTRUCT) {
	dns_rdata_in_httpssvc_t *httpssvc = source;

	REQUIRE(type == dns_rdatatype_httpssvc);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(httpssvc != NULL);
	REQUIRE(httpssvc->common.rdtype == type);
	REQUIRE(httpssvc->common.rdclass == rdclass);

	return (generic_fromstruct_in_svcb(CALL_FROMSTRUCT));
}

static inline isc_result_t
tostruct_in_httpssvc(ARGS_TOSTRUCT) {
	dns_rdata_in_httpssvc_t *httpssvc = target;

	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(httpssvc != NULL);
	REQUIRE(rdata->length != 0);

	return (generic_tostruct_in_svcb(CALL_TOSTRUCT));
}

static inline void
freestruct_in_httpssvc(ARGS_FREESTRUCT) {
	dns_rdata_in_httpssvc_t *httpssvc = source;

	REQUIRE(httpssvc != NULL);
	REQUIRE(httpssvc->common.rdclass == dns_rdataclass_in);
	REQUIRE(httpssvc->common.rdtype == dns_rdatatype_httpssvc);

	generic_freestruct_in_svcb(CALL_FREESTRUCT);
}

static inline isc_result_t
additionaldata_in_httpssvc(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	return (generic_additionaldata_in_svcb(CALL_ADDLDATA));
}

static inline isc_result_t
digest_in_httpssvc(ARGS_DIGEST) {
	isc_region_t region1;

	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_rdata_toregion(rdata, &region1);
	return ((digest)(arg, &region1));
}

static inline bool
checkowner_in_httpssvc(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_httpssvc);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (true);
}

static inline bool
checknames_in_httpssvc(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_httpssvc);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	return (generic_checknames_in_svcb(CALL_CHECKNAMES));
}

static inline int
casecompare_in_httpssvc(ARGS_COMPARE) {
	return (compare_in_httpssvc(rdata1, rdata2));
}

#endif /* RDATA_IN_1_HTTPSSVC_65482_C */
