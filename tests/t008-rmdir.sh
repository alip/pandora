#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox rmdir(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t008_rmdir

test_expect_success setup '
    mkdir dir0 &&
    mkdir dir1 &&
    mkdir dir4 &&
    mkdir dir5
'

test_expect_success 'deny rmdir()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog dir0 &&
    test_path_is_dir dir0
'

test_expect_success ATTACH 'attach & deny rmdir()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog dir1
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_dir dir1
'

test_expect_success 'deny rmdir() for non-existant directory' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        $prog dir2-non-existant
'

test_expect_success ATTACH 'attach & deny rmdir() for non-existant directory' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog dir3-non-existant
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_expect_success 'allow rmdir()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $prog dir4 &&
    test_path_is_missing dir4
'

test_expect_success ATTACH 'attach & allow rmdir()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog dir5
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test_path_is_missing dir5
'

test_done
