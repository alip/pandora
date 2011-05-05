#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox mknod(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t007_mknod

test_expect_success FIFOS setup '
    mknod fifo1 p
'

test_expect_success FIFOS 'deny mknod()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog fifo0-non-existant &&
    test_path_is_missing fifo0-non-existant
'

test_expect_success FIFOS 'deny mknod() for existant fifo' '
    test_must_violate pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/write:deny \
        -- $prog fifo1
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success FIFOS,MKTEMP 'deny mknod() for existant fifo outside' '
    (
        ff="$(mkstemp --dry-run)"
        test -n "$ff" &&
        mknod "$ff" p &&
        test_must_violate pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/write:deny \
            -m "whitelist/write+$HOME_ABSOLUTE/**" \
            -- $prog "$ff"
    )
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
            -m core/sandbox/write:deny \
            -m "whitelist/write+$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside
    )
'

test_expect_success FIFOS 'allow mknod()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_ABSOLUTE/**" \
        -- $prog fifo2-non-existant &&
    test_path_is_fifo fifo2-non-existant
'

test_expect_success FIFOS,MKTEMP 'allow mknod() for non-existant fifo outside' '
    (
        ff="$(mkstemp --dry-run)"
        test -n "$ff" &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/write:deny \
            -m "whitelist/write+$TEMPORARY_DIRECTORY/**" \
            -- $prog "$ff" &&
        test -p "$ff"
    ) || return 1
'

test_done
