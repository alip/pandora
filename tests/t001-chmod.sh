#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chmod()'
. ./test-lib.sh

test_expect_success setup '
    touch file0 &&
    chmod 600 file0 &&
    touch file1 &&
    chmod 600 file1 &&
    touch file2 &&
    chmod 600 file2 &&
    touch file3 &&
    chmod 600 file3 &&
    touch file4 &&
    chmod 600 file4 &&
    touch file5 &&
    chmod 600 file5 &&
    touch file6 &&
    chmod 600 file6 &&
    rm -f file-non-existant
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling &&
    ln -sf file2 symlink-file2 &&
    ln -sf file3 symlink-file3 &&
    ln -sf file5 symlink-file5 &&
    ln -sf file6 symlink-file6
'

test_expect_success 'deny chmod()' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY/t001_chmod file0
    test $? = 128 &&
    test $(stat -c "%a" file0) = 600
'

test_expect_success ATTACH 'attach & deny chmod()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY/t001_chmod file1
    ) &
    pandora -m core/sandbox_path:1 -p $!
    test $? = 128 &&
    test $(stat -c "%a" file1) = 600
'

test_expect_code 128 'deny chmod() for non-existant file' '
    pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY/t001_chmod file-non-existant
'

test_expect_code ATTACH 128 'attach & deny chmod() for non-existant file' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $TEST_DIRECTORY/t001_chmod file-non-existant
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success SYMLINKS 'deny chmod() for symbolic link' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY/t001_chmod symlink-file2
    test $? = 128 &&
    test $(stat -c "%a" file2) = 600
'

test_expect_success SYMLINKS 'attach & deny chmod() for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY/t001_chmod symlink-file3
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -p $!
    test $? = 128 &&
    test $(stat -c "%a" file3) = 600
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny chmod() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        chmod 600 "$f" &&
        ln -sf "$f" symlink0-outside &&
        pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox_path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $TEST_DIRECTORY/t001_chmod symlink0-outside
        test $? = 128 &&
        test $(stat -c "%a" "$f") = 600
    ) || return 1
'

test_expect_code ATTACH,MKTEMP,SYMLINKS 128 'attach & deny chmod() for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY/t001_chmod symlink1-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" symlink1-outside &&
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_expect_code SYMLINKS 128 'deny chmod() for dangling symbolic link' '
    pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY/t001_chmod symlink-dangling
'

test_expect_code ATTACH,SYMLINKS 128 'attach & deny chmod() for dangling symbolic link' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $TEST_DIRECTORY/t001_chmod symlink-dangling
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'allow chmod()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $TEST_DIRECTORY/t001_chmod file3 &&
    test $(stat -c "%s" file3) = 0
'

test_expect_success ATTACH 'attach & allow chmod()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY/t001_chmod file4
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test $(stat -c "%s" file4) = 0
'

test_expect_success SYMLINKS 'allow chmod() for symbolic link' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        $TEST_DIRECTORY/t001_chmod symlink-file5 &&
    test $(stat -c "%s" file5) = 0
'

test_expect_success ATTACH,SYMLINKS 'attach & allow chmod() for symbolic link' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY/t001_chmod symlink-file6
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test $(stat -c "%s" file6) = 0
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow chmod() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        chmod 600 "$f" &&
        ln -sf "$f" symlink2-outside &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox_path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            $TEST_DIRECTORY/t001_chmod symlink2-outside &&
        test $(stat -c "%s" "$f") = 0
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & allow chmod() for symbolic link outside' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY/t001_chmod symlink3-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" symlink3-outside &&
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEMPORARY_DIRECTORY/**" \
        -p $! &&
    test $(stat -c "%s" "$f") = 0
'

test_done
