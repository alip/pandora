#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox creat(2)'
. ./test-lib.sh

test_expect_success setup '
    rm -f file0-non-existant &&
    rm -f file1-non-existant &&
    touch file2 &&
    touch file3
'

test_expect_success 'deny creat()' '
    pandora \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t004_creat file0-non-existant
    test $? = 128 &&
    test ! -e file0-non-existant
'

test_expect_success ATTACH 'attach & deny creat()' '
    (
        sleep 1
        $TEST_DIRECTORY/t004_creat file1-non-existant
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -p $!
    test $? = 128 &&
    test ! -e file1-non-existant
'

test_expect_success 'allow creat()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        $TEST_DIRECTORY/t004_creat file2 "3" &&
    test -n "$(cat file2)"
'

test_expect_success ATTACH 'attach & allow creat()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY/t004_creat file3 "3"
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -p $! &&
    test -n "$(cat file3)"
'

test_done
