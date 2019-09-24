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

setup () {
	zone="$1"
	echo_i "setting up zone: $zone"
	zonefile="${zone}.db"
	echo $zone >> zones
}

#
# Set up zones that will be initially signed.
#
for zn in default rsasha1 dnssec-keygen some-keys legacy-keys pregenerated \
	  rsasha1-nsec3 rsasha256 rsasha512 ecdsa256 ecdsa384
do
	setup "${zn}.kasp"
	cp template.db.in $zonefile
done

# Some of these zones already have keys.
zone="dnssec-keygen.kasp"
$KEYGEN -k rsasha1 -l policies/kasp.conf $zone > keygen.out.$zone.1 2>&1

zone="some-keys.kasp"
$KEYGEN -P none -A none -a RSASHA1 -b 2000 -L 1234 $zone > keygen.out.$zone.1 2>&1
$KEYGEN -P none -A none -a RSASHA1 -f KSK  -L 1234 $zone > keygen.out.$zone.2 2>&1

zone="legacy.kasp"
$KEYGEN -a RSASHA1 -b 2000 -L 1234 $zone > keygen.out.$zone.1 2>&1
$KEYGEN -a RSASHA1 -f KSK  -L 1234 $zone > keygen.out.$zone.2 2>&1

zone="pregenerated.kasp"
$KEYGEN -k rsasha1 -l policies/kasp.conf $zone > keygen.out.$zone.1 2>&1
$KEYGEN -k rsasha1 -l policies/kasp.conf $zone > keygen.out.$zone.2 2>&1

#
# Set up zones that are already signed.
#

# These signatures are set to expire long in the past, update immediately.
setup expired-sigs.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 300 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 300 $zone 2> keygen.out.$zone.2`
$SETTIME -s -P now-6mo -A now-6mo -g OMNIPRESENT -d OMNIPRESENT -k OMNIPRESENT -r OMNIPRESENT $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P now-6mo -A now-6mo -g OMNIPRESENT -k OMNIPRESENT -z OMNIPRESENT $ZSK > settime.out.$zone.2 2>&1
$SIGNER -PS -s now-2mo -e now-1mo -o $zone -O full -f $zonefile template.db.in > signer.out.$zone.1 2>&1

# These signatures are still good, but not fresh enough, update immediately.
setup unfresh-sigs.autosign
KSK=`$KEYGEN -a ECDSAP256SHA256 -f KSK -L 300 $zone 2> keygen.out.$zone.1`
ZSK=`$KEYGEN -a ECDSAP256SHA256 -L 300 $zone 2> keygen.out.$zone.2`
$SETTIME -s -P now-6mo -A now-6mo -g OMNIPRESENT -d OMNIPRESENT -k OMNIPRESENT -r OMNIPRESENT $KSK > settime.out.$zone.1 2>&1
$SETTIME -s -P now-6mo -A now-6mo -g OMNIPRESENT -k OMNIPRESENT -z OMNIPRESENT $ZSK > settime.out.$zone.2 2>&1
$SIGNER -S -s now-1w -e now+1w -o $zone -O full -f $zonefile template.db.in > signer.out.$zone.1 2>&1
