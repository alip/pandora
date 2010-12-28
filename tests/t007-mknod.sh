#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox mknod(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t007_mknod

test_expect_success FIFOS setup '
    mknod fifo2 p &&
    mknod fifo3 p
'

test_expect_success FIFOS 'deny mknod()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog fifo0-non-existant &&
    test_path_is_missing fifo0-non-existant
'

test_expect_success ATTACH,FIFOS 'attach & deny mknod()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog fifo1-non-existant
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing fifo1-non-existant
'

test_expect_success FIFOS 'deny mknod() for existant fifo' '
    test_must_violate pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -- $prog fifo2
'

test_expect_success ATTACH,FIFOS 'attach & deny mknod() for existant fifo' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog fifo3
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success FIFOS,MKTEMP 'deny mknod() for existant fifo outside' '
    (
        ff="$(mkstemp --dry-run)"
        test -n "$ff" &&
        mknod "$ff" p &&
        test_must_violate pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog "$ff"
    )
'

test_expect_success ATTACH,FIFOS,MKTEMP,TODO 'attach & deny mknod() for existant fifo outside' '
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success FIFOS,MKTEMP,SYMLINKS 'deny mknod() for symlink outside' '
    (
        ff="$(mkstemp --dry-run)"
        test -n "$ff" &&
        mknod "$ff" p &&
        ln -sf "$ff" symlink0-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside
    )
'

test_expect_success ATTACH,FIFOS,MKTEMP,SYMLINKS 'attach & deny mknod() for symlink outside' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog symlink1-outside
    ) &
    pid=$!
    ff="$(mkstemp --dry-run)"
    test -n "$ff" &&
    mknod "$ff" p &&
    ln -sf "$ff" symlink1-outside &&
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_expect_success FIFOS 'allow mknod()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $prog fifo6-non-existant &&
    test_path_is_fifo fifo6-non-existant
'

test_expect_success ATTACH 'attach & allow mknod()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog fifo7-non-existant
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test_path_is_fifo fifo7-non-existant
'

test_expect_success FIFOS,MKTEMP 'allow mknod() for non-existant fifo outside' '
    (
        ff="$(mkstemp --dry-run)"
        test -n "$ff" &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            -- $prog "$ff" &&
        test -p "$ff"
    ) || return 1
'

test_expect_success FIFOS,MKTEMP,TODO 'attach & allow mknod() for non-existant fifo outside' '
'

test_done
