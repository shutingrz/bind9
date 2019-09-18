#!/bin/sh -e
#
# Copyright (C) Internet Systems Consortium, Inc. ("ISC")
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# See the COPYRIGHT file distributed with this work for additional
# information regarding copyright ownership.

# shellcheck source=conf.sh
. "$SYSTEMTESTTOP/conf.sh"

echo_i "ns3/setup.sh"

infile="template.db.in"

for zone in default configured configured-with-keys \
	    configured-with-some-keys configured-with-used-keys \
	    configured-with-pregenerated
do
	zonefile="${zone}.kasp.db"
	cp $infile $zonefile
done

zone="configured-with-keys.kasp"
$KEYGEN -k configured -l policies/configured.conf $zone > keygen.out.$zone.1 2>&1

zone="configured-with-some-keys.kasp"
$KEYGEN -P none -A none -a RSASHA512 -b 2000 -L 1234 $zone > keygen.out.$zone.1 2>&1
$KEYGEN -P none -A none -a RSASHA512 -f KSK  -L 1234 $zone > keygen.out.$zone.2 2>&1

zone="configured-with-used-keys.kasp"
$KEYGEN -a RSASHA512 -b 2000 -L 1234 $zone > keygen.out.$zone.1 2>&1
$KEYGEN -a RSASHA512 -f KSK  -L 1234 $zone > keygen.out.$zone.2 2>&1

zone="configured-with-pregenerated.kasp"
$KEYGEN -k configured -l policies/configured.conf $zone > keygen.out.$zone.1 2>&1
$KEYGEN -k configured -l policies/configured.conf $zone > keygen.out.$zone.2 2>&1
