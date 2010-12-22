#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='basic sanity checks'
. ./test-lib.sh

test_expect_success 'pandora' '
    pandora -V >/dev/null
'

test_expect_success 'wildmatch' '
    $TEST_DIRECTORY_ABSOLUTE/wildtest -i $TEST_DIRECTORY_ABSOLUTE/wildtest.txt
'

test_done
