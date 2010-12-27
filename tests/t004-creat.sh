#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox creat(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t004_creat

test_expect_success setup '
    rm -f file0-non-existant &&
    rm -f file1-non-existant &&
    touch file2 &&
    touch file3 &&
    rm -f file4-non-existant &&
    rm -f file5-non-existant
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf file4-non-existant symlink-dangling-file4 &&
    ln -sf file5-non-existant symlink-dangling-file5
'

test_expect_success 'deny creat()' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file0-non-existant
    test $? = 128 &&
    test ! -e file0-non-existant
'

test_expect_success ATTACH 'attach & deny creat()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY/t004_creat file1-non-existant
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -p $!
    test $? = 128 &&
    test ! -e file1-non-existant
'

test_expect_success SYMLINKS 'deny creat() for dangling symbolic link' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-dangling-file4
    test $? = 128 &&
    test ! -e file4-non-existant
'

test_expect_success ATTACH,SYMLINKS 'attach & deny creat() for dangling symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-dangling-file5
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -p $!
    test $? = 128 &&
    test ! -e file5-non-existant
'
# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny creat() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        ln -sf "$f" symlink0-outside &&
        pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside "3"
        test $? = 128 &&
        test -z "$(cat "$f")"
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & deny creat() for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink1-outside "3"
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    ln -sf "$f" symlink1-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
    test $? = 128 &&
    test -z "$(cat "$f")"
'

test_expect_success 'allow creat()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
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
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -p $! &&
    test -n "$(cat file3)"
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow creat() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        ln -sf "$f" symlink2-outside &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            $prog symlink2-outside "3" &&
        test -n "$(cat "$f")"
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & allow chmod() for symbolic link outside' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog symlink3-outside "3"
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    ln -sf "$f" symlink3-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$TEMPORARY_DIRECTORY/**" \
        -p $! &&
    test -n "$(cat "$f")"
'

test_done
