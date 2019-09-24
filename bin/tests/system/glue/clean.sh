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

REALPWD=$(realpath "$PWD")

if [ -r "$REALPWD/.gitignore" ]; then
    while read -r FILE; do
	REALFILE=$(realpath -m "$REALPWD/$FILE")
	# shellcheck disable=SC2086
	rm -rf $REALFILE
    done < "$REALPWD/.gitignore"
fi
