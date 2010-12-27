#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox mkdir(2)'
. ./test-lib.sh

test_expect_success setup '
    mkdir dir2 &&
    mkdir dir3
'

test_expect_success SYMLINKS setup-symlinks '
'

test_expect_success 'deny mkdir()' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t006_mkdir dir0-non-existant
    test $? = 128 &&
    test ! -d dir0-non-existant
'

test_expect_success ATTACH 'attach & deny mkdir()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t006_mkdir dir1-non-existant
    ) &
    pandora -m core/sandbox/path:1 -p $!
    test $? = 128 &&
    test ! -d dir1-non-existant
'

test_expect_code 128 'deny mkdir() for existant directory' '
    pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t006_mkdir dir2
'

test_expect_code ATTACH 128 'attach & deny mkdir() for existant directory' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t006_mkdir dir3
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_done
