#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chown(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t002_chown

test_expect_success setup '
    rm -f file-non-existant &&
    touch file0 &&
    touch file1 &&
    touch file2 &&
    touch file3
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling &&
    ln -sf file1 symlink-file1 &&
    ln -sf file3 symlink-file3
'

test_expect_success 'deny chown()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file0
'

test_expect_success 'deny chown() for non-existant file' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file-non-existant
'

test_expect_success SYMLINKS 'deny chown() for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file1
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny chown() for symbolic link outside' '
    (
        f="$(mkstemp)"
        s="symlink0-outside"
        test -n "$f" &&
        ln -sf "$f" $s &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "whitelist/path+$HOME_ABSOLUTE/**" \
            -- $prog $s
    )
'

test_expect_success SYMLINKS 'deny chown() for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-dangling
'

test_expect_success 'allow chown()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "whitelist/path+$HOME_ABSOLUTE/**" \
        -- $prog file2
'

test_expect_success SYMLINKS 'allow chown() for symbolic link' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "whitelist/path+$HOME_ABSOLUTE/**" \
        $prog symlink-file3
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow chown() for symbolic link outside' '
    (
        f="$(mkstemp)"
        s="symlink1-outside"
        test -n "$f" &&
        ln -sf "$f" $s &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "whitelist/path+$TEMPORARY_DIRECTORY/**" \
            $prog $s
    )
'

test_done
