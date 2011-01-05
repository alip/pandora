#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox lchown(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t005_lchown

test_expect_success SYMLINKS setup-symlinks '
    touch file0 &&
    ln -sf file0 symlink-file0 &&
    touch file2 &&
    ln -sf file2 symlink-file2
'

test_expect_success SYMLINKS 'deny lchown()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file0
'

test_expect_success SYMLINKS 'deny lchown for non-existant file' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog file1-non-existant
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny lchown() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test_path_is_file "$f" &&
        ln -sf "$f" symlink0-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            -- $prog symlink0-outside
    )
'

test_expect_success SYMLINKS 'allow lchown()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $prog symlink-file2
'

test_done
