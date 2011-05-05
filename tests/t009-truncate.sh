#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox truncate(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t009_truncate

test_expect_success setup '
    echo foo > file0 &&
    echo foo > file2 &&
    echo foo > file3 &&
    echo foo > file4
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file2 symlink-file2 &&
    ln -sf file4 symlink-file4
'

test_expect_success 'deny truncate()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog file0 &&
    test_path_is_non_empty file0
'

test_expect_success 'deny truncate() for non-existant file' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog file1-non-existant
'

test_expect_success SYMLINKS 'deny truncate() for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog symlink-file2 &&
    test_path_is_non_empty file2
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
            -m core/sandbox/write:deny \
            -m "whitelist/write+$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside &&
        test_path_is_non_empty "$f"
    )
'

test_expect_success SYMLINKS 'deny truncate() for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog symlink-dangling
'

test_expect_success 'allow truncate()' '
    pandora -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_ABSOLUTE/**" \
        -- $prog file3 &&
    test_path_is_empty file3
'

test_expect_success SYMLINKS 'allow truncate() for symbolic link' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/write:deny \
        -m "whitelist/write+$HOME_ABSOLUTE/**" \
        $prog symlink-file4 &&
    test_path_is_empty file4
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow truncate() for symbolic link outside' '
    (
        f="$(mkstemp)"
        test_path_is_file "$f" &&
        echo foo > "$f" &&
        ln -sf "$f" symlink1-outside &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/write:deny \
            -m "whitelist/write+$TEMPORARY_DIRECTORY/**" \
            $prog symlink1-outside &&
        test_path_is_empty "$f"
    )
'

test_done
