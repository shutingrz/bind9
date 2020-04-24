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

# Creates the system tests output file from the various test output files.  It
# then searches that file and prints the number of tests passed, failed, not
# run.
#
# Usage:
#    testsummary.sh [-ns] [testnames]
#
# -n	Do NOT delete the individual test output files after concatenating
#	them into systests.output.
# -s    Skip printing the counts of failed, passed, and skipped tests.
#       (This information is unnecessary when called from the automake
#       makefile, because it generates its own summary including counts.)
#
# Status return:
# 0 - no tests failed
# 1 - one or more tests failed

SYSTEMTESTTOP=.
. $SYSTEMTESTTOP/conf.sh

keepfile=0
skip=0

while getopts "ns" flag; do
    case $flag in
	n) keepfile=1 ;;
        s) skip=1 ;;
    esac
    shift
done

# if test names weren't passed in via the command line, use the
# value TESTS, which is set in the makefile.
[ "$#" -eq 0 ] && set -- $TESTS

for file; do
    [ -f ${file}.log ] || { echo_i "MISSING:$f"; continue; }
    files="$files ${file}.log"
    found=yes
done

if [ -z "$found" ]; then
    echowarn "I:No test output files were found."
    echowarn "I:Printing summary from pre-existing 'systests.output'."
else
    cat $files > systests.output
    if [ $keepfile -eq 0 ]; then
        rm -f $files
    fi
fi

status=0
if [ "$skip" -eq 0 ]; then
    echoinfo "I:System test result summary:"
    echoinfo "`grep 'R:[a-z0-9_-][a-z0-9_-]*:[A-Z][A-Z]*' systests.output | cut -d':' -f3 | sort | uniq -c | sed -e 's/^/I:/'`"
fi

FAILED_TESTS=`grep 'R:[a-z0-9_-][a-z0-9_-]*:FAIL' systests.output | cut -d':' -f2 | sort | sed -e 's/^/I:      /'`
if [ -n "${FAILED_TESTS}" ]; then
	echoinfo "I:The following system tests failed:"
	echoinfo "${FAILED_TESTS}"
	status=1
fi

CRASHED_TESTS=`find . -name 'core*' -or -name '*.core' | cut -d'/' -f2 | sort -u | sed -e 's/^/I:      /'`
if [ -n "${CRASHED_TESTS}" ]; then
	echoinfo "I:Core dumps were found for the following system tests:"
	echoinfo "${CRASHED_TESTS}"
fi

ASSERTION_FAILED_TESTS=`find . -name named.run | xargs grep "assertion failure" | cut -d'/' -f2 | sort -u | sed -e 's/^/I:      /'`
if [ -n "${ASSERTION_FAILED_TESTS}" ]; then
	echoinfo "I:Assertion failures were detected for the following system tests:"
	echoinfo "${ASSERTION_FAILED_TESTS}"
fi

TSAN_REPORT_TESTS=`find . -name 'tsan.*' | cut -d'/' -f2 | sort -u | sed -e 's/^/I:      /'`
if [ -n "${TSAN_REPORT_TESTS}" ]; then
	echoinfo "I:ThreadSanitizer reported issues for the following system tests:"
	echoinfo "${TSAN_REPORT_TESTS}"
fi

if [ "$#" -ne 0 ]; then
    RESULTS=`grep -c 'R:[a-z0-9_-][a-z0-9_-]*:[A-Z][A-Z]*' systests.output`
    if [ "${RESULTS}" -ne "$#" ]; then
        echofail "I:Found ${RESULTS} results out of $# tests"
        status=1
    fi
fi

exit $status
