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
    ln -sf dir4 symlink-dangling-dir4 &&
    ln -sf dir5 symlink-dangling-dir5
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

test_expect_success SYMLINKS 'deny mkdir() for dangling symlink' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t006_mkdir symlink-dangling-dir4
    test $? = 128 &&
    test ! -d dir4
'

test_expect_success ATTACH,SYMLINKS 'attach & deny mkdir() for dangling symlink' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t006_mkdir symlink-dangling-dir5
    ) &
    pandora -m core/sandbox/path:1 -p $!
    test $? = 128 &&
    test ! -d dir5
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP 'deny mkdir() for existant directory outside' '
    (
        d="$(mkstemp --dry-run)"
        test -n "$d" &&
        pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $TEST_DIRECTORY_ABSOLUTE/t006_mkdir "$d"
        test $? = 128 &&
        test ! -d "$d"
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,TODO 'attach & deny mkdir() for existant directory outside' '
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny mkdir() for symlink outside' '
    (
        d="$(mkstemp -d)"
        test -d "$d" &&
        ln -sf "$d" symlink0-outside &&
        pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $TEST_DIRECTORY_ABSOLUTE/t006_mkdir symlink0-outside
        test $? = 128
    ) || return 1
'

test_expect_code ATTACH,MKTEMP,SYMLINKS 128 'attach & deny mkdir() for symlink outside' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t006_mkdir symlink1-outside
    ) &
    pid=$!
    d="$(mkstemp -d)"
    test -d "$d" &&
    ln -sf "$d" symlink1-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny mkdir() for dangling symlink outside' '
    (
        d="$(mkstemp --dry-run)"
        test -n "$d" &&
        ln -sf "$d" symlink3-outside &&
        pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $TEST_DIRECTORY_ABSOLUTE/t006_mkdir symlink3-outside
        test $? = 128 &&
        test ! -d "$d"
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & deny mkdir() dangling for symlink outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t006_mkdir symlink4-outside
    ) &
    pid=$!
    d="$(mkstemp --dry-run)"
    test -n "$d" &&
    ln -sf "$d" symlink4-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
    test $? = 128 &&
    test ! -d "$d"
'

test_expect_success 'allow mkdir()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $TEST_DIRECTORY_ABSOLUTE/t006_mkdir dir6-non-existant &&
    test -d dir6-non-existant
'

test_expect_success ATTACH 'attach & allow mkdir()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t006_mkdir dir7-non-existant
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test -d dir7-non-existant
'

test_expect_success MKTEMP 'allow mkdir() for non-existant directory outside' '
    (
        d="$(mkstemp --dry-run)"
        test -n "$d" &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            -- $TEST_DIRECTORY_ABSOLUTE/t006_mkdir "$d" &&
        test -d "$d"
    ) || return 1
'

test_expect_success MKTEMP,TODO 'attach & allow mkdir() for non-existant directory outside' '
'

test_done
