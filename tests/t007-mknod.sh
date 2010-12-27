#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox mknod(2)'
. ./test-lib.sh

test_expect_success FIFOS setup '
    mknod fifo2 p &&
    mknod fifo3 p
'

test_expect_success 'deny mknod()' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t007_mknod fifo0-non-existant
    test $? = 128 &&
    test ! -p fifo0-non-existant
'

test_expect_success ATTACH 'attach & deny mknod()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t007_mknod fifo1-non-existant
    ) &
    pandora -m core/sandbox/path:1 -p $!
    test $? = 128 &&
    test ! -p fifo1-non-existant
'

test_expect_code 128 'deny mknod() for existant fifo' '
    pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t007_mknod fifo2
'

test_expect_code ATTACH 128 'attach & deny mknod() for existant fifo' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t007_mknod fifo3
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP 'deny mknod() for existant fifo outside' '
    (
        ff="$(mkstemp --dry-run)"
        test -n "$ff" &&
        mknod "$ff" p &&
        pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $TEST_DIRECTORY_ABSOLUTE/t007_mknod "$ff"
        test $? = 128
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,TODO 'attach & deny mknod() for existant fifo outside' '
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny mknod() for symlink outside' '
    (
        ff="$(mkstemp --dry-run)"
        test -n "$ff" &&
        mknod "$ff" p &&
        ln -sf "$ff" symlink0-outside &&
        pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $TEST_DIRECTORY_ABSOLUTE/t007_mknod symlink0-outside
        test $? = 128
    ) || return 1
'

test_expect_code ATTACH,MKTEMP,SYMLINKS 128 'attach & deny mknod() for symlink outside' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t007_mknod symlink1-outside
    ) &
    pid=$!
    ff="$(mkstemp --dry-run)"
    test -n "$ff" &&
    mknod "$ff" p &&
    ln -sf "$ff" symlink1-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_expect_success 'allow mknod()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $TEST_DIRECTORY_ABSOLUTE/t007_mknod fifo6-non-existant &&
    test -p fifo6-non-existant
'

test_expect_success ATTACH 'attach & allow mknod()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t007_mknod fifo7-non-existant
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test -p fifo7-non-existant
'

test_expect_success MKTEMP 'allow mknod() for non-existant fifo outside' '
    (
        ff="$(mkstemp --dry-run)"
        test -n "$ff" &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            -- $TEST_DIRECTORY_ABSOLUTE/t007_mknod "$ff" &&
        test -p "$ff"
    ) || return 1
'

test_expect_success MKTEMP,TODO 'attach & allow mknod() for non-existant fifo outside' '
'

test_done
