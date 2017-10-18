#!/bin/sh
#
# Copyright (C) 2015, 2016  Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

. ../conf.sh

if ! $PERL -e 'use Net::DNS;' 2>/dev/null; then
    echoinfo "I:This test requires the Net::DNS library." >&2
    exit 1
fi

ret=0
$FEATURETEST --rpz-nsdname || ret=1
$FEATURETEST --rpz-nsip || ret=1

if [ $ret != 0 ]; then
    echo "I:This test requires NSIP AND NSDNAME support in RPZ." >&2
    exit 1
fi

exec $SHELL ../testcrypto.sh
