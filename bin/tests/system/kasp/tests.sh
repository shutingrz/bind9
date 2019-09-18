#!/bin/sh
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
SYSTEMTESTTOP=..
. "$SYSTEMTESTTOP/conf.sh"

status=0
n=0

###############################################################################
# Constants                                                                   #
###############################################################################
DEFAULT_TTL=300


###############################################################################
# Utilities                                                                   #
###############################################################################

# Call dig with default options.
dig_with_opts() {
	"$DIG" +tcp +noadd +nosea +nostat +nocmd +dnssec -p "$PORT" "$@"
}

# Print IDs of keys used for generating RRSIG records for RRsets of type $1
# found in dig output file $2.
get_keys_which_signed() {
	_qtype=$1
	_output=$2
	# The key ID is the 11th column of the RRSIG record line.
	awk -v qt="$_qtype" '$4 == "RRSIG" && $5 == qt {print $11}' < "$_output"
}

# Get the key ids from key files for zone $2 in directory $1
# that matches algorithm $3.
get_keyids() {
	_dir=$1
	_zone=$2
	_algorithm=$(printf "%03d" $3)
	_start="${_dir}/K${_zone}.+${_algorithm}+"
	_end=".key"

	ls ${_start}*${_end} | sed "s/$_dir\/K${_zone}.+${_algorithm}+\([0-9]\{5\}\)${_end}/\1/"
}

# By default log errors and don't quit immediately.
_log=1
_continue=1
log_error() {
	test $_log -eq 1 && echo_i "error: $1"
	ret=$((ret+1))

	test $_continue -eq 1 || exit 1
}

# TODO: Move wait_for_log to conf.sh.common
wait_for_log() {
	_msg=$1
	_file=$2

	for i in 1 2 3 4 5 6 7 8 9 10; do
		nextpart "$_file" | grep "$_msg" > /dev/null && return
		sleep 1
	done
	log_error "exceeded time limit waiting for '$_msg' in $_file"
}

# Set zone properties for testing keys.
# $1: Key directory
# $2: Zone name
# $3: Policy name
# $4: DNSKEY TTL
#
# This will set the following environment variables for testing:
# DIR, ZONE, POLICY, DNSKEY_TTL
zone_properties() {
	DIR=$1
	ZONE=$2
	POLICY=$3
	DNSKEY_TTL=$4
}

# Set key properties for testing keys.
# $1: Role
# $2: Lifetime
# $3: Algorithm (number)
# $4: Algorithm (string-format)
# $5: Algorithm length
#
# This will set the following environment variables for testing:
# KEY_ROLE, KEY_LIFETIME, ALG_NUM, ALG_STR, ALG_LEN
key_properties() {
	KEY_ROLE=$1
	KEY_LIFETIME=$2
	ALG_NUM=$3
	ALG_STR=$4
	ALG_LEN=$5
}

# Set key timing metadata. Set to "none" to unset.
# These times are hard to test, so it is just an indication that we expect the
# respective timing metadata in the key files.
# $1: Published
# $2: Active
# $3: Retired
# $4: Revoked
# $5: Removed
#
# This will set the following environment variables for testing:
# KEY_PUBLISHED, KEY_ACTIVE, KEY_RETIRED, KEY_REVOKED, KEY_REMOVED.
key_timings() {
	KEY_PUBLISHED=$1
	KEY_ACTIVE=$2
	KEY_RETIRED=$3
	KEY_REVOKED=$4
	KEY_REMOVED=$5
}

# Set key state metadata. Set to "none" to unset.
# $1: DNSKEY state
# $2: RRSIG state (zsk)
# $3: RRSIG state (ksk)
# $4: DS state
#
# This will set the following environment variables for testing:
# STATE_DNSKEY, STATE_ZRRSIG, STATE_KRRSIG, STATE_DS.
key_states() {
	STATE_DNSKEY=$1
	STATE_ZRRSIG=$2
	STATE_KRRSIG=$3
	STATE_DS=$4
}

# Check the key with key id $1.
# This requires environment variables to be set with 'zone_properties',
# 'key_properties', and 'key_timings'.
#
# This will set the following environment variables for testing:
# BASE_FILE="${_dir}/K${_zone}.+${_alg_numpad}+${_key_idpad}"
# KEY_FILE="${BASE_FILE}.key"
# PRIVATE_FILE="${BASE_FILE}.private"
# STATE_FILE="${BASE_FILE}.state"
# KEY_ID=$(echo $1 | sed 's/^0*//')
check_key() {
	_dir=$DIR
	_zone=$ZONE
	_role=$KEY_ROLE
	_key_idpad=$1
	_key_id=$(echo $_key_idpad | sed 's/^0*//')
	_alg_num=$ALG_NUM
        _alg_numpad=$(printf "%03d" $_alg_num)
	_alg_string=$ALG_STR
	_length=$ALG_LEN
	_dnskey_ttl=$DNSKEY_TTL
	_lifetime=$KEY_LIFETIME

	_ksk="no"
	_zsk="no"
	if [ "$_role" == "ksk" ]; then
		_role2="key-signing"
		_ksk="yes"
		_flags="257"
	elif [ "$_role" == "zsk" ]; then
		_role2="zone-signing"
		_zsk="yes"
		_flags="256"
	elif [ "$_role" == "csk" ]; then
		_role2="key-signing"
		_zsk="yes"
		_ksk="yes"
		_flags="257"
	fi

	BASE_FILE="${_dir}/K${_zone}.+${_alg_numpad}+${_key_idpad}"
	KEY_FILE="${BASE_FILE}.key"
	PRIVATE_FILE="${BASE_FILE}.private"
	STATE_FILE="${BASE_FILE}.state"
	KEY_ID="${_key_id}"

	test $_log -eq 1 && echo_i "check key $KEY_ID"

	# Check the public key file.
	grep "This is a ${_role2} key, keyid ${_key_id}, for ${_zone}." $KEY_FILE > /dev/null || log_error "mismatch top comment in $KEY_FILE"
	grep "${_zone}\. ${_dnskey_ttl} IN DNSKEY ${_flags} 3 ${_alg_num}" $KEY_FILE > /dev/null || log_error "mismatch DNSKEY record in $KEY_FILE"
	# Now check the private key file.
	grep "Private-key-format: v1.3" $PRIVATE_FILE > /dev/null || log_error "mismatch private key format in $PRIVATE_FILE"
	grep "Algorithm: ${_alg_num} (${_alg_string})" $PRIVATE_FILE > /dev/null || log_error "mismatch algorithm in $PRIVATE_FILE"
	# Now check the key state file.
	grep "This is the state of key ${_key_id}, for ${_zone}." $STATE_FILE > /dev/null || log_error "mismatch top comment in $STATE_FILE"
	grep "Lifetime: ${_lifetime}" $STATE_FILE > /dev/null || log_error "mismatch lifetime in $STATE_FILE"
	grep "Algorithm: ${_alg_num}" $STATE_FILE > /dev/null || log_error "mismatch algorithm in $STATE_FILE"
	grep "Length: ${_length}" $STATE_FILE > /dev/null || log_error "mismatch length in $STATE_FILE"
	grep "KSK: ${_ksk}" $STATE_FILE > /dev/null || log_error "mismatch ksk in $STATE_FILE"
	grep "ZSK: ${_zsk}" $STATE_FILE > /dev/null || log_error "mismatch zsk in $STATE_FILE"

	# Check key states.
	if [ $STATE_DNSKEY == "none" ]; then
		grep "DNSKEYState: " $STATE_FILE > /dev/null && log_error "unexpected dnskey state in $STATE_FILE"
	else
		grep "DNSKEYState: ${STATE_DNSKEY}" $STATE_FILE > /dev/null || log_error "mismatch dnskey state in $STATE_FILE"
	fi

	if [ $STATE_ZRRSIG == "none" ]; then
		grep "ZRRSIGState: " $STATE_FILE > /dev/null && log_error "unexpected zrrsig state in $STATE_FILE"
	else
		grep "ZRRSIGState: ${STATE_ZRRSIG}" $STATE_FILE > /dev/null || log_error "mismatch zrrsig state in $STATE_FILE"
	fi

	if [ $STATE_KRRSIG == "none" ]; then
		grep "KRRSIGState: " $STATE_FILE > /dev/null && log_error "unexpected krrsig state in $STATE_FILE"
	else
		grep "KRRSIGState: ${STATE_KRRSIG}" $STATE_FILE > /dev/null || log_error "mismatch krrsig state in $STATE_FILE"
	fi

	if [ $STATE_DS == "none" ]; then
		grep "DSState: " $STATE_FILE > /dev/null && log_error "unexpected ds state in $STATE_FILE"
	else
		grep "DSState: ${STATE_DS}" $STATE_FILE > /dev/null || log_error "mismatch ds state in $STATE_FILE"
	fi

	# Check timing metadata.
	if [ $KEY_PUBLISHED == "none" ]; then
		grep "; Publish:" $KEY_FILE > /dev/null && log_error "unexpected publish comment in $KEY_FILE"
		grep "Publish:" $PRIVATE_FILE > /dev/null && log_error "unexpected publish in $PRIVATE_FILE"
		grep "Published: " $STATE_FILE > /dev/null && log_error "unexpected publish in $STATE_FILE"
	else
		grep "; Publish:" $KEY_FILE > /dev/null || log_error "mismatch publish comment in $KEY_FILE ($KEY_PUBLISHED)"
		grep "Publish:" $PRIVATE_FILE > /dev/null || log_error "mismatch publish in $PRIVATE_FILE ($KEY_PUBLISHED)"
		grep "Published:" $STATE_FILE > /dev/null || log_error "mismatch publish in $STATE_FILE ($KEY_PUBLISHED)"
	fi

	if [ $KEY_ACTIVE == "none" ]; then
		grep "; Activate:" $KEY_FILE > /dev/null && log_error "unexpected active comment in $KEY_FILE"
		grep "Activate:" $PRIVATE_FILE > /dev/null && log_error "unexpected active in $PRIVATE_FILE"
		grep "Active: " $STATE_FILE > /dev/null && log_error "unexpected active in $STATE_FILE"
	else
		grep "; Activate:" $KEY_FILE > /dev/null || log_error "mismatch active comment in $KEY_FILE"
		grep "Activate:" $PRIVATE_FILE > /dev/null || log_error "mismatch active in $PRIVATE_FILE"
		grep "Active: " $STATE_FILE > /dev/null || log_error "mismatch active in $STATE_FILE"
	fi

	if [ $KEY_RETIRED == "none" ]; then
		grep "; Inactive:" $KEY_FILE > /dev/null && log_error "unexpected retired comment in $KEY_FILE"
		grep "Inactive:" $PRIVATE_FILE > /dev/null && log_error "unexpected retired in $PRIVATE_FILE"
		grep "Retired: " $STATE_FILE > /dev/null && log_error "unexpected retired in $STATE_FILE"
	else
		grep "; Inactive:" $KEY_FILE > /dev/null || log_error "mismatch retired comment in $KEY_FILE"
		grep "Inactive:" $PRIVATE_FILE > /dev/null || log_error "mismatch retired in $PRIVATE_FILE"
		grep "Retired: " $STATE_FILE > /dev/null || log_error "mismatch retired in $STATE_FILE"
	fi

	if [ $KEY_REVOKED == "none" ]; then
		grep "; Revoke:" $KEY_FILE > /dev/null && log_error "unexpected revoked comment in $KEY_FILE"
		grep "Revoke:" $PRIVATE_FILE > /dev/null && log_error "unexpected revoked in $PRIVATE_FILE"
		grep "Revoked: " $STATE_FILE > /dev/null && log_error "unexpected revoked in $STATE_FILE"
	else
		grep "; Revoke:" $KEY_FILE > /dev/null || log_error "mismatch revoked comment in $KEY_FILE"
		grep "Revoke:" $PRIVATE_FILE > /dev/null || log_error "mismatch revoked in $PRIVATE_FILE"
		grep "Revoked: " $STATE_FILE > /dev/null || log_error "mismatch revoked in $STATE_FILE"
	fi

	if [ $KEY_REMOVED == "none" ]; then
		grep "; Delete:" $KEY_FILE > /dev/null && log_error "unexpected removed comment in $KEY_FILE"
		grep "Delete:" $PRIVATE_FILE > /dev/null && log_error "unexpected removed in $PRIVATE_FILE"
		grep "Removed: " $STATE_FILE > /dev/null && log_error "unexpected removed in $STATE_FILE"
	else
		grep "; Delete:" $KEY_FILE > /dev/null || log_error "mismatch removed comment in $KEY_FILE"
		grep "Delete:" $PRIVATE_FILE > /dev/null || log_error "mismatch removed in $PRIVATE_FILE"
		grep "Removed: " $STATE_FILE > /dev/null || log_error "mismatch removed in $STATE_FILE"
	fi

	grep "; Created:" $KEY_FILE > /dev/null || log_error "mismatch created comment in $KEY_FILE"
	grep "Created:" $PRIVATE_FILE > /dev/null || log_error "mismatch created in $PRIVATE_FILE"
	grep "Generated: " $STATE_FILE > /dev/null || log_error "mismatch generated in $STATE_FILE"
}

# Check the key with key id $1 and see if it is unused.
# This requires environment variables to be set with 'zone_properties',
# and 'key_properties'.
#
# This will set the following environment variables for testing:
# BASE_FILE="${_dir}/K${_zone}.+${_alg_numpad}+${_key_idpad}"
# KEY_FILE="${BASE_FILE}.key"
# PRIVATE_FILE="${BASE_FILE}.private"
# STATE_FILE="${BASE_FILE}.state"
# KEY_ID=$(echo $1 | sed 's/^0*//')
key_unused() {
	_dir=$DIR
	_zone=$ZONE
	_key_idpad=$1
	_key_id=$(echo $_key_idpad | sed 's/^0*//')
	_alg_num=$ALG_NUM
        _alg_numpad=$(printf "%03d" $_alg_num)

	BASE_FILE="${_dir}/K${_zone}.+${_alg_numpad}+${_key_idpad}"
	KEY_FILE="${BASE_FILE}.key"
	PRIVATE_FILE="${BASE_FILE}.private"
	STATE_FILE="${BASE_FILE}.state"
	KEY_ID="${_key_id}"

	test $_log -eq 1 && echo_i "key unused $KEY_ID?"

	# Check timing metadata.
	grep "; Publish:" $KEY_FILE > /dev/null && log_error "unexpected publish comment in $KEY_FILE"
	grep "Publish:" $PRIVATE_FILE > /dev/null && log_error "unexpected publish in $PRIVATE_FILE"
	grep "Published: " $STATE_FILE > /dev/null && log_error "unexpected publish in $STATE_FILE"
	grep "; Activate:" $KEY_FILE > /dev/null && log_error "unexpected active comment in $KEY_FILE"
	grep "Activate:" $PRIVATE_FILE > /dev/null && log_error "unexpected active in $PRIVATE_FILE"
	grep "Active: " $STATE_FILE > /dev/null && log_error "unexpected active in $STATE_FILE"
	grep "; Inactive:" $KEY_FILE > /dev/null && log_error "unexpected retired comment in $KEY_FILE"
	grep "Inactive:" $PRIVATE_FILE > /dev/null && log_error "unexpected retired in $PRIVATE_FILE"
	grep "Retired: " $STATE_FILE > /dev/null && log_error "unexpected retired in $STATE_FILE"
	grep "; Revoke:" $KEY_FILE > /dev/null && log_error "unexpected revoked comment in $KEY_FILE"
	grep "Revoke:" $PRIVATE_FILE > /dev/null && log_error "unexpected revoked in $PRIVATE_FILE"
	grep "Revoked: " $STATE_FILE > /dev/null && log_error "unexpected revoked in $STATE_FILE"
	grep "; Delete:" $KEY_FILE > /dev/null && log_error "unexpected removed comment in $KEY_FILE"
	grep "Delete:" $PRIVATE_FILE > /dev/null && log_error "unexpected removed in $PRIVATE_FILE"
	grep "Removed: " $STATE_FILE > /dev/null && log_error "unexpected removed in $STATE_FILE"
}

# Test: dnssec-verify zone $1.
dnssec_verify()
{
	_zone=$1

	n=$((n+1))
	echo_i "dnssec-verify zone ${_zone} ($n)"
	ret=0
	dig_with_opts $_zone @10.53.0.3 AXFR > dig.out.axfr.test$n || log_error "dig ${_zone} AXFR failed"
	$VERIFY -z -o $_zone dig.out.axfr.test$n > /dev/null || log_error "dnssec verify zone $_zone failed"
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

###############################################################################
# Tests                                                                       #
###############################################################################

#
# dnssec-keygen
#
zone_properties "keys" "kasp" "kasp" "200"

n=$((n+1))
echo_i "check that 'dnssec-keygen -k' (configured policy) creates valid files ($n)"
ret=0
$KEYGEN -K keys -k $POLICY -l kasp.conf $ZONE > keygen.out.kasp.test$n 2>/dev/null || ret=1
lines=$(cat keygen.out.kasp.test$n | wc -l)
test "$lines" -eq 4 || log_error "wrong number of keys created for policy kasp: $lines"
# Temporarily don't log errors because we are searching multiple files.
_log=0
# Check one algorithm.
key_properties "csk" "31536000" "13" "ECDSAP256SHA256" "256"
key_timings "none" "none" "none" "none" "none"
key_states "none" "none" "none" "none"
id=$(get_keyids $DIR $ZONE $ALG_NUM)
check_key $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))
# Check the other algorithm.
ids=$(get_keyids $DIR $ZONE "8")
for id in $ids; do
	# There are three key files with the same algorithm.
	# Check them until a match is found.
	ret=0
	key_properties "ksk" "31536000" "8" "RSASHA256" "2048"
	key_states "none" "none" "none" "none"
	check_key $id
	test "$ret" -eq 0 && continue

	ret=0
	key_properties "zsk" "2592000" "8" "RSASHA256" "1024"
	key_states "none" "none" "none" "none"
	check_key $id
	test "$ret" -eq 0 && continue

	ret=0
	key_properties "zsk" "16070400" "8" "RSASHA256" "2000"
	key_states "none" "none" "none" "none"
	check_key $id

	# If ret is still non-zero, non of the files matched.
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
done
# Turn error logs on again.
_log=1

n=$((n+1))
echo_i "check that 'dnssec-keygen -k' (default policy) creates valid files ($n)"
ret=0
zone_properties "." "kasp" "_default" "3600"
key_properties "csk" "0" "13" "ECDSAP256SHA256" "256"
key_timings "none" "none" "none" "none" "none"
key_states "none" "none" "none" "none"
$KEYGEN -k $POLICY $ZONE > keygen.out._default.test$n 2>/dev/null || ret=1
lines=$(cat keygen.out._default.test$n | wc -l)
test "$lines" -eq 1 || log_error "wrong number of keys created for policy _default: $lines"
id=$(get_keyids $DIR $ZONE $ALG_NUM)
check_key $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-keygen -k' (default policy) creates valid files ($n)"
ret=0
zone_properties "." "kasp" "_default" "3600"
key_properties "KEY1" "csk" "0" "13" "ECDSAP256SHA256" "256" "yes"
key_timings "KEY1" "none" "none" "none" "none" "none"
key_states "KEY1" "none" "none" "none" "none" "none"
$KEYGEN -k $POLICY $ZONE > keygen.out.$POLICY.test$n 2>/dev/null || ret=1
lines=$(cat keygen.out._default.test$n | wc -l)
test "$lines" -eq 1 || log_error "wrong number of keys created for policy _default: $lines"
id=$(get_keyids $DIR $ZONE "${KEY1[$ALG_NUM]}")
check_key "KEY1" $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

#
# dnssec-settime
#

# These test builds upon the latest created key with dnssec-keygen and uses the
# environment variables BASE_FILE, KEY_FILE, PRIVATE_FILE and STATE_FILE.
CMP_FILE="${BASE_FILE}.cmp"
n=$((n+1))
echo_i "check that 'dnssec-settime' by default does not edit key state file ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
$SETTIME -P +3600 $BASE_FILE > /dev/null || log_error "settime failed"
grep "; Publish: " $KEY_FILE > /dev/null || log_error "mismatch published in $KEY_FILE"
grep "Publish: " $PRIVATE_FILE > /dev/null || log_error "mismatch published in $PRIVATE_FILE"
$DIFF $CMP_FILE $STATE_FILE || log_error "unexpected file change in $STATE_FILE"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-settime -s' also sets time metadata in key state file ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
now=$(date +%Y%m%d%H%M%S)
$SETTIME -s -P $now $BASE_FILE > /dev/null || log_error "settime failed"
key_timings "set" "none" "none" "none" "none"
key_states "none" "none" "none" "none"
check_key $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

n=$((n+1))
echo_i "check that 'dnssec-settime -s' also unsets time metadata in key state file ($n)"
ret=0
cp $STATE_FILE $CMP_FILE
$SETTIME -s -P none $BASE_FILE > /dev/null || log_error "settime failed"
key_timings "none" "none" "none" "none" "none"
key_states "none" "none" "none" "none"
check_key $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

#
# named
#

#
# Zone: default.kasp.
#

# Check the zone with default kasp policy has loaded and is signed.
zone_properties "ns3" "default.kasp" "_default" "3600"

n=$((n+1))
echo_i "check key is created for zone ${ZONE} ($n)"
ret=0
key_properties "csk" "0" "13" "ECDSAP256SHA256" "256"
# The first key is immediately published and activated.
key_timings "set" "set" "none" "none" "none" "none"
# DNSKEY, RRSIG (ksk), RRSIG (zsk) are published. DS needs to wait.
key_states "rumoured" "rumoured" "rumoured" "hidden"
wait_for_log "DNSKEY .* created for policy $POLICY" "${DIR}/named.run"
nextpartreset "${DIR}/named.run"
id=$(get_keyids $DIR $ZONE $ALG_NUM)
check_key $id
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Verify signed zone.
dnssec_verify $ZONE

# Test DNSKEY query.
QTYPE="DNSKEY"
n=$((n+1))
echo_i "check ${QTYPE} rrset is signed correctly for zone ${ZONE} ($n)"
ret=0
dig_with_opts $ZONE @10.53.0.3 $QTYPE > dig.out.$DIR.test$n || log_error "dig ${ZONE} ${QTYPE} failed"
grep "status: NOERROR" dig.out.$DIR.test$n > /dev/null || log_error "mismatch status in DNS response"
grep "${ZONE}\..*${DNSKEY_TTL}.*IN.*${QTYPE}.*257.*.3.*${ALG_NUM}" dig.out.$DIR.test$n > /dev/null || log_error "missing ${QTYPE} record in response"
lines=$(get_keys_which_signed $QTYPE dig.out.$DIR.test$n | wc -l)
test "$lines" -eq 1 || log_error "bad number ($lines) of RRSIG records in DNS response"
get_keys_which_signed $QTYPE dig.out.$DIR.test$n | grep "^$KEY_ID$" > /dev/null || log_error "${QTYPE} RRset not signed with ${CHECK_KSK_ID}"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

# Test SOA query.
QTYPE="SOA"
n=$((n+1))
echo_i "check ${QTYPE} rrset is signed correctly for zone ${ZONE} ($n)"
ret=0
dig_with_opts $ZONE @10.53.0.3 $QTYPE > dig.out.$DIR.test$n || log_error "dig ${ZONE} ${QTYPE} failed"
grep "status: NOERROR" dig.out.$DIR.test$n > /dev/null || log_error "mismatch status in DNS response"
grep "${ZONE}\..*${DEFAULT_TTL}.*IN.*${QTYPE}.*mname1\..*\." dig.out.$DIR.test$n > /dev/null || log_error "missing ${QTYPE} record in response"
lines=$(get_keys_which_signed $QTYPE dig.out.$DIR.test$n | wc -l)
test "$lines" -eq 1 || log_error "bad number ($lines) of RRSIG records in DNS response"
get_keys_which_signed $QTYPE dig.out.$DIR.test$n | grep "^$KEY_ID$" > /dev/null || log_error "${QTYPE} RRset not signed with ${CHECK_KSK_ID}"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

#
# Zone: configured.kasp.
#

# Check the zone with manual policy has loaded and is signed as expected.
zone_properties "ns3" "configured.kasp" "configured" "1234"

# There are no keys created, so total of three keys (KSK, 2x ZSK) should be
# created after first run.
n=$((n+1))
echo_i "check number of keys for zone ${ZONE} ($n)"
ret=0
numkeys=$(get_keyids $DIR $ZONE "10" | wc -l)
test "$numkeys" -eq 3 || log_error "bad number ($numkeys) of key files for zone $ZONE (expected 3)"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

check_configured_zone()
{
	n=$((n+1))
	echo_i "check keys are created for zone ${ZONE} ($n)"
	ret=0

	# The first key is immediately published and activated.
	# Because lifetime > 0, retired timing is also set.
	key_timings "set" "set" "set" "none" "none"

	# Temporarily don't log errors because we are searching multiple files.
	_log=0

	# Clear key ids.
	KSK_ID=
	ZSK_ID1=
	ZSK_ID2=

	# Check key files.
	ids=$(get_keyids $DIR $ZONE "10")
	for id in $ids; do
		# There are three key files with the same algorithm.
		# Check them until a match is found.
		echo_i "check key $id"

		ret=0
		key_properties "ksk" "315360000" "10" "RSASHA512" "2048"
		# DNSKEY, RRSIG (ksk) published. DS needs to wait.
		key_states "rumoured" "none" "rumoured" "hidden"
		check_key $id
		test "$ret" -eq 0 && KSK_ID=$KEY_ID && continue

		ret=0
		# DNSKEY, RRSIG (zsk) published.
		key_states "rumoured" "rumoured" "none" "none"
		key_properties "zsk" "157680000" "10" "RSASHA512" "1024"
		check_key $id
		test "$ret" -eq 0 && ZSK_ID1=$KEY_ID && continue

		ret=0
		# DNSKEY, RRSIG (zsk) published.
		key_states "rumoured" "rumoured" "none" "none"
		key_properties "zsk" "31536000" "10" "RSASHA512" "2000" && check_key $id
		test "$ret" -eq 0 && ZSK_ID2=$KEY_ID && continue

		# This may be an unused key.
		ret=0
		key_unused $id
		test "$ret" -eq 0 && continue

		# If ret is still non-zero, non of the files matched.
		test "$ret" -eq 0 || echo_i "failed"
		status=$((status+ret))
	done

	# Turn error logs on again.
	_log=1

	ret=0
	test -n "$KSK_ID" || log_error "No KSK found for zone ${ZONE}"
	test -n "$ZSK_ID1" || log_error "No ZSK1 found for zone ${ZONE}"
	test -n "$ZSK_ID2" || log_error "No ZSK2 found for zone ${ZONE}"
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))

	# Verify signed zone.
	dnssec_verify $ZONE

	# Test DNSKEY query.
	QTYPE="DNSKEY"
	n=$((n+1))
	echo_i "check ${QTYPE} rrset is signed correctly for zone ${ZONE} ($n)"
	ret=0
	dig_with_opts $ZONE @10.53.0.3 $QTYPE > dig.out.$DIR.test$n || log_error "dig ${ZONE} ${QTYPE} failed"
	grep "status: NOERROR" dig.out.$DIR.test$n > /dev/null || log_error "mismatch status in DNS response"
	grep "${ZONE}\..*${DNSKEY_TTL}.*IN.*${QTYPE}.*257.*.3.*${ALG_NUM}" dig.out.$DIR.test$n > /dev/null || log_error "missing ${QTYPE} record in response"
	lines=$(get_keys_which_signed $QTYPE dig.out.$DIR.test$n | wc -l)
	test "$lines" -eq 1 || log_error "bad number of RRSIG records in DNS response"
	get_keys_which_signed $QTYPE dig.out.$DIR.test$n | grep "^$KSK_ID$" > /dev/null || log_error "${QTYPE} RRset not signed with ${KSK_ID}"
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))

	# Test SOA query.
	QTYPE="SOA"
	n=$((n+1))
	echo_i "check ${QTYPE} rrset is signed correctly for zone ${ZONE} ($n)"
	ret=0
	dig_with_opts $ZONE @10.53.0.3 $QTYPE > dig.out.$DIR.test$n || log_error "dig ${ZONE} ${QTYPE} failed"
	grep "status: NOERROR" dig.out.$DIR.test$n > /dev/null || log_error "mismatch status in DNS response"
	grep "${ZONE}\..*${DEFAULT_TTL}.*IN.*${QTYPE}.*mname1\..*\." dig.out.$DIR.test$n > /dev/null || log_error "missing ${QTYPE} record in response"
	lines=$(get_keys_which_signed $QTYPE dig.out.$DIR.test$n | wc -l)
	test "$lines" -eq 2 || log_error "bad number of RRSIG records in DNS response"
	get_keys_which_signed $QTYPE dig.out.$DIR.test$n | grep "^$ZSK_ID1$" > /dev/null || log_error "${QTYPE} RRset not signed with ${ZSK_ID1}"
	get_keys_which_signed $QTYPE dig.out.$DIR.test$n | grep "^$ZSK_ID2$" > /dev/null || log_error "${QTYPE} RRset not signed with ${ZSK_ID2}"
	test "$ret" -eq 0 || echo_i "failed"
	status=$((status+ret))
}

check_configured_zone

#
# Zone: configured-with-keys.kasp.
#

# Check the zone with manual policy has loaded and is signed as expected.
zone_properties "ns3" "configured-with-keys.kasp" "configured" "1234"
key_timings "set" "set" "none" "none" "none"

# There are no new keys created, so total of three keys (KSK, 2x ZSK) exist.
n=$((n+1))
echo_i "check number of keys for zone ${ZONE} ($n)"
ret=0
numkeys=$(get_keyids $DIR $ZONE "10" | wc -l)
test "$numkeys" -eq 3 || log_error "bad number ($numkeys) of key files for zone $ZONE (expected 3)"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

check_configured_zone

#
# Zone: configured-with-some-keys.kasp.
#

# Check the zone with manual policy has loaded and is signed as expected.
zone_properties "ns3" "configured-with-some-keys.kasp" "configured" "1234"
key_timings "set" "set" "none" "none" "none"

# Two keys already exist (KSK, ZSK), so only one key (ZSK) should be
# created by named, bringing the total to three (KSK, 2x ZSK).
n=$((n+1))
echo_i "check number of keys for zone ${ZONE} ($n)"
ret=0
numkeys=$(get_keyids $DIR $ZONE "10" | wc -l)
test "$numkeys" -eq 3 || log_error "bad number ($numkeys) of key files for zone $ZONE (expected 3)"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

check_configured_zone

#
# Zone: configured-with-used-keys.kasp.
#

# Check the zone with manual policy has loaded and is signed as expected.
zone_properties "ns3" "configured-with-used-keys.kasp" "configured" "1234"
key_timings "set" "set" "none" "none" "none"

# Two keys already exist (KSK, ZSK), so only one key (ZSK) should be
# created by named, bringing the total to three (KSK, 2x ZSK).
n=$((n+1))
echo_i "check number of keys for zone ${ZONE} ($n)"
ret=0
numkeys=$(get_keyids $DIR $ZONE "10" | wc -l)
test "$numkeys" -eq 3 || log_error "bad number ($numkeys) of key files for zone $ZONE (expected 3)"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

check_configured_zone

#
# Zone: configured-with-pregenerated.kasp.
#

# Check the zone with manual policy has loaded and is signed as expected.
zone_properties "ns3" "configured-with-pregenerated.kasp" "configured" "1234"
key_timings "set" "set" "none" "none" "none"

# Six keys already pregenerated.
n=$((n+1))
echo_i "check number of keys for zone ${ZONE} ($n)"
ret=0
numkeys=$(get_keyids $DIR $ZONE "10" | wc -l)
test "$numkeys" -eq 6 || log_error "bad number ($numkeys) of key files for zone $ZONE (expected 6)"
test "$ret" -eq 0 || echo_i "failed"
status=$((status+ret))

check_configured_zone

echo_i "exit status: $status"
[ $status -eq 0 ] || exit 1
