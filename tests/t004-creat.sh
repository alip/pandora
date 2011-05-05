#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox creat(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t004_creat

test_expect_success setup '
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf file1-non-existant symlink-file1
'

test_expect_success 'deny creat()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog file0-non-existant &&
    test_path_is_missing file0-non-existant
'

test_expect_success SYMLINKS 'deny creat() for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog symlink-file1 &&
    test_path_is_missing file1-non-existant
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny creat() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test_path_is_file "$f" &&
        ln -sf "$f" symlink0-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/write:deny \
            -m "whitelist/write+$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside "3" &&
        test_path_is_empty "$f"
    )
'

test_expect_success 'allow creat()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_ABSOLUTE/*" \
        $TEST_DIRECTORY/t004_creat file2-non-existant "3" &&
    test_path_is_non_empty file2-non-existant
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow creat() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test_path_is_file "$f" &&
        ln -sf "$f" symlink1-outside &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/write:deny \
            -m "whitelist/write+$TEMPORARY_DIRECTORY/**" \
            $prog symlink1-outside "3" &&
        test_path_is_non_empty "$f"
    )
'

test_done
