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
    touch file1 &&
    ln -sf file1 symlink-file1 &&
    touch file6 &&
    ln -sf file6 symlink-file6 &&
    touch file7 &&
    ln -sf file7 symlink-file7
'

test_expect_success SYMLINKS 'deny lchown()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file0
'

test_expect_success ATTACH,SYMLINKS 'attach & deny lchown()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-file1
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_expect_success SYMLINKS 'deny lchown for non-existant file' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog file2-non-existant
'

test_expect_success ATTACH,SYMLINKS 'attach & deny chown() for non-existant file' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog file3-non-existant
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny lchown() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test_path_is_file "$f" &&
        ln -sf "$f" symlink4-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            -- $prog symlink4-outside
    )
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & deny lchown() for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink5-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test_path_is_file "$f" &&
    ln -sf "$f" symlink5-outside &&
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$TEMPORARY_DIRECTORY/**" \
        -p $!
'

test_expect_success SYMLINKS 'allow lchown()' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $prog symlink-file6
'

test_expect_success ATTACH,SYMLINKS 'attach & allow lchown()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog symlink-file7
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_done
