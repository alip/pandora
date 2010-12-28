#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chmod()'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t001_chmod

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
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file0 &&
    test_path_is_readable file0 &&
    test_path_is_writable file0
'

test_expect_success ATTACH 'attach & deny chmod()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file1
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_readable file0 &&
    test_path_is_writable file0
'

test_expect_success 'deny chmod() for non-existant file' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog file-non-existant
'

test_expect_success ATTACH 'attach & deny chmod() for non-existant file' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog file-non-existant
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_expect_success SYMLINKS 'deny chmod() for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file2 &&
    test_path_is_readable file2 &&
    test_path_is_writable file2
'

test_expect_success SYMLINKS 'attach & deny chmod() for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-file3
    ) &
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -p $! &&
    test_path_is_readable file2 &&
    test_path_is_writable file2
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny chmod() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        chmod 600 "$f" &&
        ln -sf "$f" symlink0-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside &&
            test_path_is_readable file2 &&
            test_path_is_writable file2
    )
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & deny chmod() for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink1-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" symlink1-outside &&
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_expect_success SYMLINKS 'deny chmod() for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-dangling
'

test_expect_success ATTACH,SYMLINKS 'attach & deny chmod() for dangling symbolic link' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog symlink-dangling
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_expect_success 'allow chmod()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $prog file3 &&
    test_path_is_not_readable file3 &&
    test_path_is_not_writable file3
'

test_expect_success ATTACH 'attach & allow chmod()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog file4
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test_path_is_not_readable file4 &&
    test_path_is_not_writable file4
'

test_expect_success SYMLINKS 'allow chmod() for symbolic link' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        $prog symlink-file5 &&
    test_path_is_not_readable file5 &&
    test_path_is_not_writable file5
'

test_expect_success ATTACH,SYMLINKS 'attach & allow chmod() for symbolic link' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog symlink-file6
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test_path_is_not_readable file6 &&
    test_path_is_not_writable file6
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
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            $prog symlink2-outside &&
        test_path_is_not_readable "$f" &&
        test_path_is_not_writable "$f"
    )
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & allow chmod() for symbolic link outside' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog symlink3-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    chmod 600 "$f" &&
    ln -sf "$f" symlink3-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$TEMPORARY_DIRECTORY/**" \
        -p $! &&
    test_path_is_not_readable "$f" &&
    test_path_is_not_writable "$f"
'

test_done
