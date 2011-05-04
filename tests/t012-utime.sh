#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox utime(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t012_utime

# No allow tests because of possible noatime, nomtime mount options

test_expect_success setup '
    rm -f file-non-existant
    touch file0 &&
    touch file1
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/path symlink-dangling &&
    ln -sf file1 symlink-file1
'

test_expect_success 'deny utime()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file0
'

test_expect_success 'deny utime()' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file-non-existant
'

test_expect_success 'deny utime() for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file1
'

test_expect_success 'deny utime() for symbolic link outside' '
    (
        f="$(mkstemp)"
        s="symlink0-outside"
        test -n "$f" &&
        ln -sf "$f" $s &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "whitelist/path+$HOME_ABSOLUTE/**" \
            -- $prog $s
    )
'

test_expect_success 'deny utime() for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-dangling
'

test_done
