#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox umount(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t010_umount

test_expect_success setup '
    mkdir mnt0 &&
    mkdir mnt1 &&
    mkdir mnt4 &&
    mkdir mnt5
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/directory symlink-dangling
    ln -sf mnt4 symlink-mnt4 &&
    ln -sf mnt5 symlink-mnt5
'

test_expect_code 128 'deny umount()' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog mnt0
'

test_expect_code ATTACH 128 'attach & deny umount()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog mnt1
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_expect_code 128 'deny umount() for non-existant directory' '
    pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog mnt2-non-existant
'

test_expect_code ATTACH 128 'attach & deny umount() for non-existant directory' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog mnt3-non-existant
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_expect_code SYMLINKS 128 'deny umount() for symbolic link' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-mnt4
'

test_expect_code ATTACH,SYMLINKS 128 'attach & deny umount() for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-mnt5
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -p $!
'

## FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny umount() for symbolic link outside' '
    (
        d="$(mkstemp -d)"
        test -d "$d" &&
        ln -sf "$d" symlink0-outside &&
        pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside
        test $? = 128
    ) || return 1
'

test_expect_code ATTACH,MKTEMP,SYMLINKS 128 'attach & deny umount() for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink1-outside
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

test_expect_code SYMLINKS 128 'deny umount() for dangling symbolic link' '
    pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-dangling
'

test_expect_code ATTACH,SYMLINKS 128 'attach & deny umount() for dangling symbolic link' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog symlink-dangling
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_done
