#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox creat(2)'
. ./test-lib.sh

test_expect_success setup '
    rm -f file0 &&
    rm -f file1 &&
    touch file2 &&
    touch file3
'

test_expect_success 'deny creat(2)' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t004_creat file0 0 &&
    test ! -e file0
'

test_expect_success ATTACH 'deny creat(2) (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t004_creat file1 0
    ) &
    pandora -m core/sandbox_path:1 -p $! &&
    test ! -e file1
'

test_expect_success 'allow creat(2)' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" $TEST_DIRECTORY/t004_creat file2 1 "3" &&
    test -n "$(cat file2)"
'

test_expect_success ATTACH 'allow creat(2) (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t004_creat file3 1 "3"
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $! &&
    test -n $(cat file3)
'

test_done
