#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox truncate(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t009_truncate

test_expect_success setup '
    echo foo > file0 &&
    echo foo > file1 &&
    echo foo > file2 &&
    echo foo > file3 &&
    echo foo > file4 &&
    echo foo > file5 &&
    echo foo > file6 &&
    echo foo > file7
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file2 symlink-file2 &&
    ln -sf file3 symlink-file3 &&
    ln -sf file6 symlink-file6 &&
    ln -sf file7 symlink-file7
'

test_expect_success 'deny truncate()' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file0
    test $? = 128 &&
    test -n "$(cat file0)"
'

test_expect_success ATTACH 'attach & deny truncate()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file1
    ) &
    pandora -m core/sandbox/path:1 -p $!
    test $? = 128 &&
    test -n "$(cat file1)"
'

test_expect_code 128 'deny truncate() for non-existant file' '
    pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog file2-non-existant
'

test_expect_code ATTACH 128 'attach & deny truncate() for non-existant file' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog file3-non-existant
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_expect_success SYMLINKS 'deny truncate() for symbolic link' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file2
    test $? = 128 &&
    test -n "$(cat file2)"
'

test_expect_success ATTACH,SYMLINKS 'attach & deny truncate() for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-file3
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -p $!
    test $? = 128 &&
    test -n "$(cat file3)"
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny truncate() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        echo foo > "$f" &&
        ln -sf "$f" symlink0-outside &&
        pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside
        test $? = 128 &&
        test -n "$(cat "$f")"
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & deny truncate() for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink1-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    echo foo > "$f" &&
    ln -sf "$f" symlink1-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
    test $? = 128 &&
    test -n "$(cat "$f")"
'

test_expect_code SYMLINKS 128 'deny truncate() for dangling symbolic link' '
    pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-dangling
'

test_expect_code ATTACH,SYMLINKS 128 'attach & deny truncate() for dangling symbolic link' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog symlink-dangling
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_expect_success 'allow truncate()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $prog file4 &&
    test -z "$(cat file4)"
'

test_expect_success ATTACH 'attach & allow truncate()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog file5
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test -z "$(cat file5)"
'

test_expect_success SYMLINKS 'allow truncate() for symbolic link' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        $prog symlink-file6 &&
    test -z "$(cat file6)"
'

test_expect_success ATTACH,SYMLINKS 'attach & allow truncate() for symbolic link' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog symlink-file7
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test -z "$(cat file7)"
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow truncate() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -e "$f" &&
        echo foo > "$f" &&
        ln -sf "$f" symlink2-outside &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            $prog symlink2-outside &&
        test -z "$(cat "$f")"
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & allow truncate() for symbolic link outside' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog symlink3-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test -e "$f" &&
    echo foo > "$f" &&
    ln -sf "$f" symlink3-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$TEMPORARY_DIRECTORY/**" \
        -p $! &&
    test -z "$(cat "$f")"
'

test_done
