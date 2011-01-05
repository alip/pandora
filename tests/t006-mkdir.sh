#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox mkdir(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t006_mkdir

test_expect_success setup '
    mkdir dir1 &&
    mkdir dir3
'

test_expect_success 'deny mkdir()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog dir0-non-existant &&
    test_path_is_missing dir0-non-existant
'

test_expect_success 'deny mkdir() for existant directory' '
    test_must_violate pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -- $prog dir1
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP 'deny mkdir() for existant directory outside' '
    (
        d="$(mkstemp -d)"
        test_path_is_dir "$d" &&
        test_must_violate pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/path:1 \
            -- $prog "$d"
    )
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny mkdir() for symlink outside' '
    (
        d="$(mkstemp -d)"
        test_path_is_dir "$d" &&
        ln -sf "$d" symlink0-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EEXIST=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside
    )
'

test_expect_success 'allow mkdir()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $prog dir2-non-existant &&
    test_path_is_dir dir2-non-existant
'

test_expect_success MKTEMP 'allow mkdir() for non-existant directory outside' '
    (
        d="$(mkstemp --dry-run)"
        test -n "$d" &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            -- $prog "$d" &&
        test_path_is_dir "$d"
    )
'

test_expect_success MKTEMP,TODO 'attach & allow mkdir() for non-existant directory outside' '
'

test_done
