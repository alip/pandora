#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox rmdir(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t008_rmdir

test_expect_success setup '
    mkdir dir0 &&
    mkdir dir2
'

test_expect_success 'deny rmdir()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:deny \
        -- $prog dir0 &&
    test_path_is_dir dir0
'

test_expect_success 'deny rmdir() for non-existant directory' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:deny \
        $prog dir1-non-existant
'

test_expect_success 'allow rmdir()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:deny \
        -m "whitelist/path+$HOME_ABSOLUTE/**" \
        -- $prog dir2 &&
    test_path_is_missing dir2
'

test_done
