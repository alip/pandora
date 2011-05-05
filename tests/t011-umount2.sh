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
    mkdir mnt2
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/directory symlink-dangling &&
    ln -sf mnt2 symlink-mnt2
'

test_expect_success 'deny umount2()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog mnt0
'

test_expect_success 'deny umount2() for non-existant directory' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog mnt1-non-existant
'

test_expect_success SYMLINKS 'deny umount2() for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog symlink-mnt2
'

## FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny umount2() for symbolic link outside' '
    (
        d="$(mkstemp -d)"
        test_path_is_dir "$d" &&
        ln -sf "$d" symlink0-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/write:deny \
            -m "whitelist/write+$HOME_ABSOLUTE/**" \
            -- $prog symlink0-outside
    )
'

test_expect_success SYMLINKS 'deny umount2() for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/write:deny \
        -- $prog symlink-dangling
'

test_done
