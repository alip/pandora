#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

# TODO: Test UMOUNT_NOFOLLOW

test_description='sandbox umount2(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t011_umount2

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

test_expect_success 'deny umount2()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog mnt0
'

test_expect_success ATTACH 'attach & deny umount2()' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog mnt1
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_expect_success 'deny umount2() for non-existant directory' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog mnt2-non-existant
'

test_expect_success ATTACH 'attach & deny umount2() for non-existant directory' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog mnt3-non-existant
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_expect_success SYMLINKS 'deny umount2() for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-mnt4
'

test_expect_success ATTACH,SYMLINKS 'attach & deny umount2() for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-mnt5
    ) &
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -p $!
'

## FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny umount2() for symbolic link outside' '
    (
        d="$(mkstemp -d)"
        test_path_is_dir "$d" &&
        ln -sf "$d" symlink0-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside
    )
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & deny umount2() for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink1-outside
    ) &
    pid=$!
    d="$(mkstemp -d)"
    test_path_is_dir "$d" &&
    ln -sf "$d" symlink1-outside &&
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $!
'

test_expect_success SYMLINKS 'deny umount2() for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-dangling
'

test_expect_success ATTACH,SYMLINKS 'attach & deny umount2() for dangling symbolic link' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog symlink-dangling
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_done
