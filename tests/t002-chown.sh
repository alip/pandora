#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chown(2)'
. ./test-lib.sh

test_expect_success setup '
    touch file0 &&
    touch file1 &&
    touch file2 &&
    touch file3 &&
    touch file4 &&
    touch file5 &&
    touch file6 &&
    rm -f file-non-existant
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling &&
    ln -sf file2 symlink-file2 &&
    ln -sf file3 symlink-file3 &&
    ln -sf file5 symlink-file5 &&
    ln -sf file6 symlink-file6
'

test_expect_code 128 'deny chown()' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t002_chown file0
'

test_expect_code ATTACH 128 'attach & deny chown()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t002_chown file1
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_expect_code 128 'deny chown() for non-existant file' '
    pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t002_chown file-non-existant
'

test_expect_code ATTACH 128 'attach & deny chown() for non-existant file' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t002_chown file-non-existant
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_expect_code SYMLINKS 128 'deny chown() for symbolic link' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink-file2
'

test_expect_code SYMLINKS 128 'attach & deny chown() for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink-file3
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -p $!
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny chown() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        ln -sf "$f" symlink0-outside &&
        pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink0-outside
        test $? = 128
    ) || return 1
'

test_expect_code ATTACH,MKTEMP,SYMLINKS 128 'attach & deny chown() for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink1-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    ln -sf "$f" symlink1-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_expect_code SYMLINKS 128 'deny chown() for dangling symbolic link' '
    pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink-dangling
'

test_expect_code ATTACH,SYMLINKS 128 'attach & deny chown() for dangling symbolic link' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink-dangling
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_expect_success 'allow chown()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $TEST_DIRECTORY_ABSOLUTE/t002_chown file3
'

test_expect_success ATTACH 'attach & allow chown()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t002_chown file4
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_expect_success SYMLINKS 'allow chown() for symbolic link' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink-file5
'

test_expect_success ATTACH,SYMLINKS 'attach & allow chown() for symbolic link' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink-file6
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow chown() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        ln -sf "$f" symlink2-outside &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink2-outside
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & allow chown() for symbolic link outside' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t002_chown symlink3-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    ln -sf "$f" symlink3-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$TEMPORARY_DIRECTORY/**" \
        -p $!
'

test_done
