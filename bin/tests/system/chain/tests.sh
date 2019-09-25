#!/bin/sh
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=../conf.sh
. "$SYSTEMTESTTOP/conf.sh"

test_description="CHAIN tests."

# shellcheck source=../sharness/lib/sharness/sharness.sh
. "$SYSTEMTESTTOP/sharness/lib/sharness/sharness.sh"

if test -n "$PYTHON" && "$PYTHON" -c 'import dns' 2>/dev/null
then
    test_set_prereq DNSPYTHON
fi

if test -n "$PERL" && "$PERL" -e 'use Net::DNS;' 2>/dev/null
then
    if "$PERL" -e 'use Net::DNS; die if ($Net::DNS::VERSION >= 0.69 && $Net::DNS::VERSION <= 0.74' 2>/dev/null
    then
	test_set_prereq NETDNS
    fi
    if "$PERL" -e 'use Net::DNS::Nameserver'
    then
	test_set_prereq NETDNSNAMESERVER
    fi
fi

dig_with_opts() {
    "$DIG" -p "$PORT" "$@"
}

rndccmd() {
    "$RNDC" -c "$SYSTEMTESTTOP/common/rndc.conf" -p "${CONTROLPORT}" -s "$@"
}

sendcmd() {
    "$PERL" "$SYSTEMTESTTOP/send.pl" 10.53.0.4 "${EXTRAPORT1}"
}

grep_dig() {
    __file=$1
    __rcode=$2
    __answers=$3
    if [ -n "$__rcode" ]; then
	grep -q -F "status: $__rcode" "$__file" || return 1
    fi
    if [ -n "$__answers" ]; then
	grep -q -F "ANSWER: $__answers" "$__file" || return 1
    fi
    return 0
}

test_expect_success "checking short DNAME from authoritative " "
  dig_with_opts a.short-dname.example @10.53.0.2 a > dig.out &&
  grep_dig dig.out NOERROR
"

test_expect_success "checking short DNAME from recursive " "
  dig_with_opts a.short-dname.example @10.53.0.7 a > dig.out &&
  grep_dig dig.out NOERROR
"

test_expect_success "checking long DNAME from authoritative " "
  dig_with_opts a.long-dname.example @10.53.0.2 a > dig.out &&
  grep_dig dig.out NOERROR
"

test_expect_success "checking long DNAME from recursive " "
  dig_with_opts a.long-dname.example @10.53.0.7 a > dig.out &&
  grep_dig dig.out NOERROR
"

test_expect_success "checking (too) long DNAME from authoritative " "
  dig_with_opts 01234567890123456789012345678901234567890123456789.longlonglonglonglonglonglonglonglonglonglonglonglonglonglong.longlonglonglonglonglonglonglonglonglonglonglonglonglonglong.longlonglonglonglonglonglonglonglonglonglonglonglonglonglong.long-dname.example @10.53.0.2 a > dig.out &&
  grep_dig dig.out YXDOMAIN
"

test_expect_success "checking (too) long DNAME from recursive with cached DNAME" "
  dig_with_opts 01234567890123456789012345678901234567890123456789.longlonglonglonglonglonglonglonglonglonglonglonglonglonglong.longlonglonglonglonglonglonglonglonglonglonglonglonglonglong.longlonglonglonglonglonglonglonglonglonglonglonglonglonglong.long-dname.example @10.53.0.7 a > dig.out &&
  grep_dig dig.out YXDOMAIN &&
  grep -q '^long-dname\.example\..*DNAME.*long' dig.out
"

test_expect_success "checking (too) long DNAME from recursive without cached DNAME" "
  dig_with_opts 01234567890123456789012345678901234567890123456789.longlonglonglonglonglonglonglonglonglonglonglonglonglonglong.longlonglonglonglonglonglonglonglonglonglonglonglonglonglong.longlonglonglonglonglonglonglonglonglonglonglonglonglong.toolong-dname.example @10.53.0.7 a > dig.out &&
  grep_dig dig.out YXDOMAIN
  grep -q '^toolong-dname\.example\..*DNAME.*long' dig.out
"

test_expect_success "checking CNAME to DNAME from authoritative" "
  dig_with_opts cname.example @10.53.0.2 a > dig.out &&
  grep_dig dig.out NOERROR
"

test_expect_success "checking CNAME to DNAME from recursive" "
  dig_with_opts cname.example @10.53.0.7 a > dig.out &&
  grep_dig dig.out NOERROR &&
  grep -q '^cname.example.' dig.out &&
  grep -q '^cnamedname.example.' dig.out &&
  grep -q '^a.cnamedname.example.' dig.out &&
  grep -q '^a.target.example.' dig.out
"

test_expect_success "checking DNAME is returned with synthesized CNAME before DNAME" "
  dig_with_opts @10.53.0.7 name.synth-then-dname.example.broken A > dig.out &&
  grep_dig dig.out NXDOMAIN &&
  grep -q '^name.synth-then-dname\.example\.broken\..*CNAME.*name.$' dig.out &&
  grep -q '^synth-then-dname\.example\.broken\..*DNAME.*\.$' dig.out
"

test_expect_success "checking DNAME is returned with CNAME to synthesized CNAME before DNAME" "
  dig_with_opts @10.53.0.7 cname-to-synth2-then-dname.example.broken A > dig.out &&
  grep_dig dig.out NXDOMAIN &&
  grep -q '^cname-to-synth2-then-dname\.example\.broken\..*CNAME.*name\.synth2-then-dname\.example\.broken.$' dig.out &&
  grep -q '^name\.synth2-then-dname\.example\.broken\..*CNAME.*name.$' dig.out &&
  grep -q '^synth2-then-dname\.example\.broken\..*DNAME.*\.$' dig.out
"

test_expect_success "checking CNAME loops are detected" "
  dig_with_opts @10.53.0.7 loop.example > dig.out &&
  grep_dig dig.out NOERROR 17
"

test_expect_success "checking CNAME to external delegated zones is handled" "
  dig_with_opts @10.53.0.7 a.example > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking CNAME to internal delegated zones is handled" "
  dig_with_opts @10.53.0.7 b.example > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking CNAME to signed external delgation is handled" "
  dig_with_opts @10.53.0.7 c.example > dig.out &&
  grep_dig dig.out NOERROR
"

test_expect_success "checking CNAME to signed internal delgation is handled" "
  dig_with_opts @10.53.0.7 d.example > dig.out &&
  grep_dig dig.out NOERROR
"

test_expect_success "checking CNAME chains in various orders (1)" "
  echo 'cname,cname,cname|1,2,3,4,s1,s2,s3,s4' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking CNAME chains in various orders (2)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'cname,cname,cname|1,1,2,2,3,4,s4,s3,s1' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking CNAME chains in various orders (3)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'cname,cname,cname|2,1,3,4,s3,s1,s2,s4' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking CNAME chains in various orders (4)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'cname,cname,cname|4,3,2,1,s4,s3,s2,s1' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking CNAME chains in various orders (5)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'cname,cname,cname|4,3,2,1,s4,s3,s2,s1' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking CNAME chains in various orders (6)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'cname,cname,cname|4,3,3,3,s1,s1,1,3,4' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking that only the initial CNAME is cached" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'cname,cname,cname|1,2,3,4,s1,s2,s3,s4' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil &&
  sleep 1 &&
  dig_with_opts +noall +answer @10.53.0.7 cname1.domain.nil > dig.out &&
  awk '{ print \$2 }' dig.out > actual &&
  echo 86400 > expected
  test_cmp actual expected
"

test_expect_success "checking DNAME chains in various orders (1)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'dname,dname|5,4,3,2,1,s5,s4,s3,s2,s1' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 3
"

test_expect_success "checking DNAME chains in various orders (2)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'dname,dname|5,4,3,2,1,s5,s4,s3,s2,s1' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 3
"

test_expect_success "checking DNAME chains in various orders (3)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'dname,dname|2,3,s1,s2,s3,s4,1' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 3
"

test_expect_success "checking external CNAME/DNAME chains in various orders (1)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'xname,dname|1,2,3,4,s1,s2,s3,s4' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking external CNAME/DNAME chains in various orders (2)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'xname,dname|s2,2,s1,1,4,s4,3' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out NOERROR 2
"

test_expect_success "checking external CNAME/DNAME chains in various orders (3)" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  echo 'xname,dname|s2,2,2,2' | sendcmd
  dig_with_opts @10.53.0.7 test.domain.nil > dig.out &&
  grep_dig dig.out SERVFAIL
"

test_expect_success "checking explicit DNAME query" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  dig_with_opts @10.53.0.7 dname short-dname.example > dig.out
  grep_dig dig.out NOERROR
"

test_expect_success "checking DNAME via ANY query" "
  rndccmd 10.53.0.7 flush 2>&1 | sed 's/^/ns7 /'
  dig_with_opts @10.53.0.7 any short-dname.example > dig.out &&
  grep_dig dig.out NOERROR
"

test_done
