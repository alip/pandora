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
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file0 &&
    test_path_is_non_empty file0
'

test_expect_success ATTACH 'attach & deny truncate()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file1
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_non_empty file1
'

test_expect_success 'deny truncate() for non-existant file' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog file2-non-existant
'

test_expect_success ATTACH 'attach & deny truncate() for non-existant file' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog file3-non-existant
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_expect_success SYMLINKS 'deny truncate() for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file2 &&
    test_path_is_non_empty file2
'

test_expect_success ATTACH,SYMLINKS 'attach & deny truncate() for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-file3
    ) &
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -p $! &&
    test_path_is_non_empty file3
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny truncate() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test_path_is_file "$f" &&
        echo foo > "$f" &&
        ln -sf "$f" symlink0-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside &&
        test_path_is_non_empty "$f"
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
    test_path_is_file "$f" &&
    echo foo > "$f" &&
    ln -sf "$f" symlink1-outside &&
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $! &&
    test_path_is_non_empty "$f"
'

test_expect_success SYMLINKS 'deny truncate() for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-dangling
'

test_expect_success ATTACH,SYMLINKS 'attach & deny truncate() for dangling symbolic link' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog symlink-dangling
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_expect_success 'allow truncate()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -- $prog file4 &&
    test_path_is_empty file4
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
    test_path_is_empty file5
'

test_expect_success SYMLINKS 'allow truncate() for symbolic link' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        $prog symlink-file6 &&
    test_path_is_empty file6
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
    test_path_is_empty file7
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow truncate() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test_path_is_file "$f" &&
        echo foo > "$f" &&
        ln -sf "$f" symlink2-outside &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$TEMPORARY_DIRECTORY/**" \
            $prog symlink2-outside &&
        test_path_is_empty "$f"
    )
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
    test_path_is_file "$f" &&
    echo foo > "$f" &&
    ln -sf "$f" symlink3-outside &&
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$TEMPORARY_DIRECTORY/**" \
        -p $! &&
    test_path_is_empty "$f"
'

test_done
