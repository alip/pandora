#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox lchown(2)'
. ./test-lib.sh

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
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t005_lchown symlink-file0
    test $? = 128
'

test_expect_code ATTACH,SYMLINKS 128 'attach & deny lchown()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t005_lchown symlink-file1
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_expect_code SYMLINKS 128 'deny lchown for non-existant file' '
    pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t005_lchown file2-non-existant
'

test_expect_code ATTACH,SYMLINKS 128 'attach & deny chown() for non-existant file' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t005_lchown file3-non-existant
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny lchown() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        ln -sf "$f" symlink4-outside &&
        pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            -- $TEST_DIRECTORY_ABSOLUTE/t005_lchown symlink4-outside
        test $? = 128
    ) || return 1
'

test_expect_code ATTACH,MKTEMP,SYMLINKS 128 'attach & deny lchown() for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t005_lchown symlink5-outside
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    ln -sf "$f" symlink5-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$TEMPORARY_DIRECTORY/**" \
        -p $!
'

test_expect_success SYMLINKS 'allow lchown()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $TEST_DIRECTORY_ABSOLUTE/t005_lchown symlink-file6
'

test_expect_success ATTACH,SYMLINKS 'attach & allow lchown()' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t005_lchown symlink-file7
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_done
