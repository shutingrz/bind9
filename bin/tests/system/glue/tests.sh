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

# shellcheck source=../conf.sh
. "$SYSTEMTESTTOP/conf.sh"

test_description="GLUE tests."

# shellcheck source=../sharness/lib/sharness/sharness.sh
. "$SYSTEMTESTTOP/sharness/lib/sharness/sharness.sh"

#
# Do glue tests.
#

dig_with_opts() {
    "$DIG" +norec -p "${PORT}" "$@"
}

test_expect_success "testing that a ccTLD referral gets a full glue set from the root zone" "
  dig_with_opts @10.53.0.1 foo.bar.fi. A >dig.out &&
  digcomp --lc '$SHARNESS_TEST_DIRECTORY'/fi.good dig.out
"

test_expect_success "testing that we don't find out-of-zone glue" "
  dig_with_opts @10.53.0.1 example.net. a > dig.out &&
  digcomp '$SHARNESS_TEST_DIRECTORY'/noglue.good dig.out
"

test_done
