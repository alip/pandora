#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chown(2)'
. ./test-lib.sh

test_expect_success setup '
    touch file0 &&
    touch file1 &&
    touch file2
'

test_expect_success 'deny chown(2)' '
    pandora -m core/sandbox_path:1 ./t002_chown file0
'

test_expect_success ATTACH 'deny chmod(2) (attach)' '
    (
        sleep 1
        ./t002_chown file0
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'allow chown(2)' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" ./t002_chown file1 1
'

test_expect_success ATTACH 'allow chmod(2) attach' '
    (
        sleep 1
        ./t002_chown file2 1
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $!
'

test_expect_success cleanup '
    rm -f file0 &&
    rm -f file1 &&
    rm -f file2
'

test_done
