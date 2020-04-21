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

#ifndef RDATA_IN_1_SVCB_65481_C
#define RDATA_IN_1_SVCB_65481_C

#define RRTYPE_SVCB_ATTRIBUTES (0)

/*
 * Service Binding Parameter Registry
 */
enum encoding {
	sbpr_text,
	sbpr_port,
	sbpr_ipv4s,
	sbpr_ipv6s,
	sbpr_base64,
	sbpr_empty
};
static const struct {
	const char *name;
	unsigned int value;
	enum encoding encoding;
	bool initial;
} sbpr[] = {
	{ "key0", 0, sbpr_text, true },
	{ "alpn", 1, sbpr_text, true },
	{ "no-default-alpn", 2, sbpr_empty, true },
	{ "port", 3, sbpr_port, true },
	{ "ipv4hint", 4, sbpr_ipv4s, true },
	{ "esniconfig", 5, sbpr_base64, true },
	{ "ipv6hint", 6, sbpr_ipv6s, true },
};

static isc_result_t
svc_fromtext(isc_textregion_t *region, isc_buffer_t *target) {
	char tbuf[sizeof("aaaa:aaaa:aaaa:aaaa:aaaa:aaaa:255.255.255.255,")];
	char abuf[16];
	isc_buffer_t sb;
	unsigned int i;
	unsigned long ul;
	char *e;
	size_t len;

#define ARRAYSIZE(x) (sizeof(x) / sizeof(*x))

	for (i = 0; i < ARRAYSIZE(sbpr); i++) {
		len = strlen(sbpr[i].name);
		if (strncasecmp(region->base, sbpr[i].name, len) != 0 ||
		    (region->base[len] != 0 && region->base[len] != '='))
		{
			continue;
		}

		if (region->base[len] == '=') {
			len++;
		}

		RETERR(uint16_tobuffer(sbpr[i].value, target));
		isc_textregion_consume(region, len);

		sb = *target;
		RETERR(uint16_tobuffer(0, target)); /* length */

		switch (sbpr[i].encoding) {
		case sbpr_text:
			RETERR(multitxt_fromtext(region, target));
			break;
		case sbpr_port:
			ul = strtoul(region->base, &e, 10);
			if (*e != '\0') {
				return (DNS_R_SYNTAX);
			}
			if (ul > 0xffff) {
				return (ISC_R_RANGE);
			}
			RETERR(uint16_tobuffer(ul, target));
			break;
		case sbpr_ipv4s:
			do {
				snprintf(tbuf, sizeof(tbuf), "%*s",
					 (int)(region->length), region->base);
				e = strchr(tbuf, ',');
				if (e != NULL) {
					*e++ = 0;
					isc_textregion_consume(region,
							       e - tbuf);
				}
				if (inet_pton(AF_INET, tbuf, abuf) != 1) {
					return (DNS_R_SYNTAX);
				}
				mem_tobuffer(target, abuf, 4);
			} while (e != NULL);
			break;
		case sbpr_ipv6s:
			do {
				snprintf(tbuf, sizeof(tbuf), "%*s",
					 (int)(region->length), region->base);
				e = strchr(tbuf, ',');
				if (e != NULL) {
					*e++ = 0;
					isc_textregion_consume(region,
							       e - tbuf);
				}
				if (inet_pton(AF_INET6, tbuf, abuf) != 1) {
					return (DNS_R_SYNTAX);
				}
				mem_tobuffer(target, abuf, 16);
			} while (e != NULL);
			break;
		case sbpr_base64:
			RETERR(isc_base64_decodestring(region->base, target));
			break;
		case sbpr_empty:
			if (region->length != 0) {
				return (DNS_R_SYNTAX);
			}
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}

		len = isc_buffer_usedlength(target) -
		      isc_buffer_usedlength(&sb) - 2;
		RETERR(uint16_tobuffer(len, &sb)); /* length */
		return (ISC_R_SUCCESS);
	}

	if (strncasecmp(region->base, "key", 3) != 0) {
		return (DNS_R_SYNTAX);
	}
	isc_textregion_consume(region, 3);
	/* No zero padding ('key0' handled above). */
	if (*region->base == '0') {
		return (DNS_R_SYNTAX);
	}
	ul = strtoul(region->base, &e, 10);
	if (*e != '=' && *e != 0) {
		return (DNS_R_SYNTAX);
	}
	if (ul > 0xffff) {
		return (ISC_R_RANGE);
	}
	RETERR(uint16_tobuffer(ul, target));
	if (*e == 0) {
		isc_textregion_consume(region, region->length);
		RETERR(uint16_tobuffer(0, target)); /* length */
		return (ISC_R_SUCCESS);
	}
	isc_textregion_consume(region, e - region->base + 1);
	sb = *target;
	RETERR(uint16_tobuffer(0, target)); /* length */
	RETERR(multitxt_fromtext(region, target));
	len = isc_buffer_usedlength(target) - isc_buffer_usedlength(&sb) - 2;
	RETERR(uint16_tobuffer(len, &sb)); /* length */
	return (ISC_R_SUCCESS);
}

static const char *
svcparamkey(unsigned short value, enum encoding *encoding, char *buf,
	    size_t len) {
	size_t i;
	int n;

	for (i = 0; i < ARRAYSIZE(sbpr); i++) {
		if (sbpr[i].value == value && sbpr[i].initial) {
			*encoding = sbpr[i].encoding;
			return (sbpr[i].name);
		}
	}
	n = snprintf(buf, len, "key%u", value);
	INSIST(n > 0 && (unsigned)n < len);
	*encoding = sbpr_text;
	return (buf);
}

static inline isc_result_t
generic_fromtext_in_svcb(ARGS_FROMTEXT) {
	isc_token_t token;
	dns_name_t name;
	isc_buffer_t buffer;
	bool alias;
#if 0
	bool ok = true;
#endif

	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	/*
	 * SvcFieldPriority.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_number,
				      false));
	if (token.value.as_ulong > 0xffffU) {
		RETTOK(ISC_R_RANGE);
	}
	RETERR(uint16_tobuffer(token.value.as_ulong, target));

	alias = token.value.as_ulong == 0;

	/*
	 * SvcDomainName.
	 */
	RETERR(isc_lex_getmastertoken(lexer, &token, isc_tokentype_qstring,
				      false));
	dns_name_init(&name, NULL);
	buffer_fromregion(&buffer, &token.value.as_region);
	if (origin == NULL) {
		origin = dns_rootname;
	}
	RETTOK(dns_name_fromtext(&name, &buffer, origin, options, target));
#if 0
	if ((options & DNS_RDATA_CHECKNAMES) != 0) {
		ok = dns_name_ishostname(&name, false);
	}
	if (!ok && (options & DNS_RDATA_CHECKNAMESFAIL) != 0) {
		RETTOK(DNS_R_BADNAME);
	}
	if (!ok && callbacks != NULL) {
		warn_badname(&name, lexer, callbacks);
	}
#endif

	if (alias) {
		return (ISC_R_SUCCESS);
	}

	/*
	 * SvcFieldValue
	 */
	while (1) {
		RETERR(isc_lex_getmastertoken(lexer, &token,
					      isc_tokentype_qvpair, true));
		if (token.type == isc_tokentype_eol ||
		    token.type == isc_tokentype_eof) {
			isc_lex_ungettoken(lexer, &token);
			return (ISC_R_SUCCESS);
		}

		if (token.type != isc_tokentype_string && /* key only */
		    token.type != isc_tokentype_qvpair &&
		    token.type != isc_tokentype_vpair)
		{
			RETERR(DNS_R_SYNTAX);
		}
		RETERR(svc_fromtext(&token.value.as_textregion, target));
	}
}

static inline isc_result_t
fromtext_in_svcb(ARGS_FROMTEXT) {
	REQUIRE(type == dns_rdatatype_svcb);
	REQUIRE(rdclass == dns_rdataclass_in);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(callbacks);

	return (generic_fromtext_in_svcb(CALL_FROMTEXT));
}

static inline isc_result_t
generic_totext_in_svcb(ARGS_TOTEXT) {
	isc_region_t region;
	dns_name_t name;
	dns_name_t prefix;
	bool sub;
	char buf[sizeof("xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:255.255.255.255")];
	unsigned short num;
	int n;

	REQUIRE(rdata->length != 0);

	dns_name_init(&name, NULL);
	dns_name_init(&prefix, NULL);

	dns_rdata_toregion(rdata, &region);

	/*
	 * SvcFieldPriority.
	 */
	num = uint16_fromregion(&region);
	isc_region_consume(&region, 2);
	n = snprintf(buf, sizeof(buf), "%u ", num);
	INSIST(n > 0 && (unsigned)n < sizeof(buf));
	RETERR(str_totext(buf, target));

	/*
	 * SvcDomainName.
	 */
	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));
	sub = name_prefix(&name, tctx->origin, &prefix);
	RETERR(dns_name_totext(&prefix, sub, target));

	while (region.length > 0) {
		isc_region_t r;
		enum encoding encoding;

		RETERR(str_totext(" ", target));

		INSIST(region.length >= 2);
		num = uint16_fromregion(&region);
		isc_region_consume(&region, 2);
		RETERR(str_totext(svcparamkey(num, &encoding, buf, sizeof(buf)),
				  target));

		INSIST(region.length >= 2);
		num = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		INSIST(region.length >= num);
		r = region;
		r.length = num;
		isc_region_consume(&region, num);
		if (num == 0) {
			continue;
		}
		RETERR(str_totext("=", target));
		switch (encoding) {
		case sbpr_text:
			RETERR(multitxt_totext(&r, target));
			break;
		case sbpr_port:
			num = uint16_fromregion(&r);
			isc_region_consume(&r, 2);
			n = snprintf(buf, sizeof(buf), "%u", num);
			INSIST(n > 0 && (unsigned)n < sizeof(buf));
			RETERR(str_totext(buf, target));
			INSIST(r.length == 0U);
			break;
		case sbpr_ipv4s:
			while (r.length > 0U) {
				INSIST(r.length >= 4U);
				inet_ntop(AF_INET, r.base, buf, sizeof(buf));
				RETERR(str_totext(buf, target));
				isc_region_consume(&r, 4);
				if (r.length != 0U) {
					RETERR(str_totext(",", target));
				}
			}
			break;
		case sbpr_ipv6s:
			while (r.length > 0U) {
				INSIST(r.length >= 16U);
				inet_ntop(AF_INET6, r.base, buf, sizeof(buf));
				RETERR(str_totext(buf, target));
				isc_region_consume(&r, 16);
				if (r.length != 0U) {
					RETERR(str_totext(",", target));
				}
			}
			break;
		case sbpr_base64:
			RETERR(isc_base64_totext(&r, 0, "", target));
			break;
		case sbpr_empty:
			INSIST(r.length == 0U);
			break;
		default:
			INSIST(0);
			ISC_UNREACHABLE();
		}
	}
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
totext_in_svcb(ARGS_TOTEXT) {
	REQUIRE(rdata->type == dns_rdatatype_svcb);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->length != 0);

	return (generic_totext_in_svcb(CALL_TOTEXT));
}

static inline isc_result_t
generic_fromwire_in_svcb(ARGS_FROMWIRE) {
	dns_name_t name;
	isc_region_t region;
	bool alias;

	UNUSED(type);
	UNUSED(rdclass);

	dns_decompress_setmethods(dctx, DNS_COMPRESS_NONE);

	dns_name_init(&name, NULL);

	/*
	 * SvcFieldPriority.
	 */
	isc_buffer_activeregion(source, &region);
	if (region.length < 2) {
		return (ISC_R_UNEXPECTEDEND);
	}
	RETERR(mem_tobuffer(target, region.base, 2));
	alias = uint16_fromregion(&region) == 0;
	isc_buffer_forward(source, 2);

	/*
	 * SvcDomainName.
	 */
	RETERR(dns_name_fromwire(&name, source, dctx, options, target));

	if (alias) {
		return (ISC_R_SUCCESS);
	}

	/*
	 * SvcFieldValue.
	 */
	isc_buffer_activeregion(source, &region);
	while (region.length > 0U) {
		unsigned short key, len;
		size_t i;

		/*
		 * SvcParamKey
		 */
		if (region.length < 2U) {
			return (ISC_R_UNEXPECTEDEND);
		}
		RETERR(mem_tobuffer(target, region.base, 2));
		key = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		/*
		 * SvcParamValue length.
		 */
		if (region.length < 2U) {
			return (ISC_R_UNEXPECTEDEND);
		}
		RETERR(mem_tobuffer(target, region.base, 2));
		len = uint16_fromregion(&region);
		isc_region_consume(&region, 2);

		/*
		 * SvcParamValue.
		 */
		if (region.length < len) {
			return (ISC_R_UNEXPECTEDEND);
		}
		for (i = 0; i < ARRAYSIZE(sbpr); i++) {
			if (sbpr[i].value == key) {
				switch (sbpr[i].encoding) {
				case sbpr_port:
					if (len != 2) {
						return (DNS_R_FORMERR);
					}
					break;
				case sbpr_ipv4s:
					if ((len % 4) != 0 || len == 0) {
						return (DNS_R_FORMERR);
					}
					break;
				case sbpr_ipv6s:
					if ((len % 16) != 0 || len == 0) {
						return (DNS_R_FORMERR);
					}
					break;
				case sbpr_text:
				case sbpr_base64:
					break;
				case sbpr_empty:
					if (len != 0) {
						return (DNS_R_FORMERR);
					}
					break;
				}
			}
		}
		RETERR(mem_tobuffer(target, region.base, len));
		isc_region_consume(&region, len);
		isc_buffer_forward(source, len + 4);
	}
	return (ISC_R_SUCCESS);
}

static inline isc_result_t
fromwire_in_svcb(ARGS_FROMWIRE) {
	REQUIRE(type == dns_rdatatype_svcb);
	REQUIRE(rdclass == dns_rdataclass_in);

	return (generic_fromwire_in_svcb(CALL_FROMWIRE));
}

static inline isc_result_t
generic_towire_in_svcb(ARGS_TOWIRE) {
	dns_name_t name;
	dns_offsets_t offsets;
	isc_region_t region;

	REQUIRE(rdata->length != 0);

	dns_compress_setmethods(cctx, DNS_COMPRESS_NONE);

	/*
	 * SvcFieldPriority.
	 */
	dns_rdata_toregion(rdata, &region);
	RETERR(mem_tobuffer(target, region.base, 2));
	isc_region_consume(&region, 2);

	/*
	 * SvcDomainName.
	 */
	dns_name_init(&name, offsets);
	dns_name_fromregion(&name, &region);
	RETERR(dns_name_towire(&name, cctx, target));
	isc_region_consume(&region, name_length(&name));

	/*
	 * SvcFieldValue.
	 */
	return (mem_tobuffer(target, region.base, region.length));
}

static inline isc_result_t
towire_in_svcb(ARGS_TOWIRE) {
	REQUIRE(rdata->type == dns_rdatatype_svcb);
	REQUIRE(rdata->length != 0);

	return (generic_towire_in_svcb(CALL_TOWIRE));
}

static inline int
compare_in_svcb(ARGS_COMPARE) {
	isc_region_t region1;
	isc_region_t region2;

	REQUIRE(rdata1->type == rdata2->type);
	REQUIRE(rdata1->rdclass == rdata2->rdclass);
	REQUIRE(rdata1->type == dns_rdatatype_svcb);
	REQUIRE(rdata1->rdclass == dns_rdataclass_in);
	REQUIRE(rdata1->length != 0);
	REQUIRE(rdata2->length != 0);

	dns_rdata_toregion(rdata1, &region1);
	dns_rdata_toregion(rdata2, &region2);

	return (isc_region_compare(&region1, &region2));
}

static inline isc_result_t
generic_fromstruct_in_svcb(ARGS_FROMSTRUCT) {
	dns_rdata_in_svcb_t *svcb = source;
	isc_region_t region;

	REQUIRE(svcb != NULL);
	REQUIRE(svcb->common.rdtype == type);
	REQUIRE(svcb->common.rdclass == rdclass);

	UNUSED(type);
	UNUSED(rdclass);

	RETERR(uint16_tobuffer(svcb->priority, target));
	dns_name_toregion(&svcb->svcdomain, &region);
	RETERR(isc_buffer_copyregion(target, &region));

	return (mem_tobuffer(target, svcb->svc, svcb->svclen));
}

static inline isc_result_t
fromstruct_in_svcb(ARGS_FROMSTRUCT) {
	dns_rdata_in_svcb_t *svcb = source;

	REQUIRE(type == dns_rdatatype_svcb);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(svcb != NULL);
	REQUIRE(svcb->common.rdtype == type);
	REQUIRE(svcb->common.rdclass == rdclass);

	return (generic_fromstruct_in_svcb(CALL_FROMSTRUCT));
}

static inline isc_result_t
generic_tostruct_in_svcb(ARGS_TOSTRUCT) {
	isc_region_t region;
	dns_rdata_in_svcb_t *svcb = target;
	dns_name_t name;

	REQUIRE(svcb != NULL);
	REQUIRE(rdata->length != 0);

	svcb->common.rdclass = rdata->rdclass;
	svcb->common.rdtype = rdata->type;
	ISC_LINK_INIT(&svcb->common, link);

	dns_rdata_toregion(rdata, &region);

	svcb->priority = uint16_fromregion(&region);
	isc_region_consume(&region, 2);

	dns_name_init(&svcb->svcdomain, NULL);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &region);
	isc_region_consume(&region, name_length(&name));

	RETERR(name_duporclone(&name, mctx, &svcb->svcdomain));
	svcb->svclen = region.length;
	svcb->svc = mem_maybedup(mctx, region.base, region.length);

	if (svcb->svc == NULL) {
		if (mctx != NULL) {
			dns_name_free(&svcb->svcdomain, svcb->mctx);
		}
		return (ISC_R_NOMEMORY);
	}

	svcb->mctx = mctx;

	return (ISC_R_SUCCESS);
}

static inline isc_result_t
tostruct_in_svcb(ARGS_TOSTRUCT) {
	dns_rdata_in_svcb_t *svcb = target;

	REQUIRE(rdata->rdclass == dns_rdataclass_in);
	REQUIRE(rdata->type == dns_rdatatype_svcb);
	REQUIRE(svcb != NULL);
	REQUIRE(rdata->length != 0);

	return (generic_tostruct_in_svcb(CALL_TOSTRUCT));
}

static inline void
generic_freestruct_in_svcb(ARGS_FREESTRUCT) {
	dns_rdata_in_svcb_t *svcb = source;

	REQUIRE(svcb != NULL);

	if (svcb->mctx == NULL) {
		return;
	}

	dns_name_free(&svcb->svcdomain, svcb->mctx);
	isc_mem_free(svcb->mctx, svcb->svc);
	svcb->mctx = NULL;
}

static inline void
freestruct_in_svcb(ARGS_FREESTRUCT) {
	dns_rdata_in_svcb_t *svcb = source;

	REQUIRE(svcb != NULL);
	REQUIRE(svcb->common.rdclass == dns_rdataclass_in);
	REQUIRE(svcb->common.rdtype == dns_rdatatype_svcb);

	generic_freestruct_in_svcb(CALL_FREESTRUCT);
}

static inline isc_result_t
generic_additionaldata_in_svcb(ARGS_ADDLDATA) {
	dns_name_t name;
	dns_offsets_t offsets;
	isc_region_t region;

	dns_name_init(&name, offsets);
	dns_rdata_toregion(rdata, &region);
	isc_region_consume(&region, 2);
	dns_name_fromregion(&name, &region);
	if (dns_name_equal(&name, dns_rootname)) {
		return (ISC_R_SUCCESS);
	}

	return ((add)(arg, &name, dns_rdatatype_a));
}

static inline isc_result_t
additionaldata_in_svcb(ARGS_ADDLDATA) {
	REQUIRE(rdata->type == dns_rdatatype_svcb);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	return (generic_additionaldata_in_svcb(CALL_ADDLDATA));
}

static inline isc_result_t
digest_in_svcb(ARGS_DIGEST) {
	isc_region_t region1;

	REQUIRE(rdata->type == dns_rdatatype_svcb);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	dns_rdata_toregion(rdata, &region1);
	return ((digest)(arg, &region1));
}

static inline bool
checkowner_in_svcb(ARGS_CHECKOWNER) {
	REQUIRE(type == dns_rdatatype_svcb);
	REQUIRE(rdclass == dns_rdataclass_in);

	UNUSED(name);
	UNUSED(type);
	UNUSED(rdclass);
	UNUSED(wildcard);

	return (true);
}

static inline bool
generic_checknames_in_svcb(ARGS_CHECKNAMES) {
#if 0
	isc_region_t region;
	dns_name_t name;
#endif

	UNUSED(rdata);
	UNUSED(bad);
	UNUSED(owner);

#if 0
	dns_rdata_toregion(rdata, &region);
	isc_region_consume(&region, 2);
	dns_name_init(&name, NULL);
	dns_name_fromregion(&name, &region);
	if (!dns_name_ishostname(&name, false)) {
		if (bad != NULL) {
			dns_name_clone(&name, bad);
		}
		return (false);
	}
#endif
	return (true);
}

static inline bool
checknames_in_svcb(ARGS_CHECKNAMES) {
	REQUIRE(rdata->type == dns_rdatatype_svcb);
	REQUIRE(rdata->rdclass == dns_rdataclass_in);

	return (generic_checknames_in_svcb(CALL_CHECKNAMES));
}

static inline int
casecompare_in_svcb(ARGS_COMPARE) {
	return (compare_in_svcb(rdata1, rdata2));
}

#endif /* RDATA_IN_1_SVCB_65481_C */
