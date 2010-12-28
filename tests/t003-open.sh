#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox open(2)'
. ./test-lib.sh
prog="$TEST_DIRECTORY_ABSOLUTE"/t003_open

test_expect_success setup '
    touch file0 &&
    rm -f file1-non-existant &&
    rm -f file2-non-existant &&
    rm -f file3-non-existant &&
    rm -f file4-non-existant &&
    touch file5 &&
    touch file6 &&
    touch file7 &&
    touch file8 &&
    rm -f file9-non-existant &&
    rm -f file10-non-existant &&
    rm -f file11-non-existant &&
    rm -f file12-non-existant &&
    touch file13 &&
    touch file14 &&
    touch file15 &&
    touch file16 &&
    rm -f file17-non-existant &&
    rm -f file18-non-existant &&
    rm -f file19-non-existant &&
    rm -f file20-non-existant &&
    touch file21 &&
    touch file22 &&
    touch file23 &&
    touch file24 &&
    rm -f file25-non-existant &&
    rm -f file26-non-existant &&
    rm -f file27-non-existant &&
    rm -f file28-non-existant &&
    touch file29 &&
    touch file30 &&
    touch file31 &&
    touch file32 &&
    rm -f file33-non-existant &&
    rm -f file34-non-existant &&
    rm -f file35-non-existant &&
    rm -f file36-non-existant &&
    touch file37 &&
    touch file38 &&
    touch file39 &&
    touch file40 &&
    rm -f file41-non-existant &&
    rm -f file42-non-existant &&
    rm -f file43-non-existant &&
    rm -f file44-non-existant &&
    touch file45 &&
    touch file46 &&
    rm -f file47-non-existant &&
    rm -f file48-non-existant &&
    touch file49 &&
    touch file50 &&
    touch file51 &&
    touch file52 &&
    rm -f file53-non-existant &&
    rm -f file54-non-existant
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling &&
    ln -sf file39 symlink-file39 &&
    ln -sf file40 symlink-file40 &&
    ln -sf file41-non-existant symlink-file41 &&
    ln -sf file42-non-existant symlink-file42 &&
    ln -sf file43-non-existant symlink-file43 &&
    ln -sf file44-non-existant symlink-file44 &&
    ln -sf file45 symlink-file45 &&
    ln -sf file46 symlink-file46 &&
    ln -sf file51 symlink-file51 &&
    ln -sf file52 symlink-file52 &&
    ln -sf file53-non-existant symlink-dangling-file53 &&
    ln -sf file54-non-existant symlink-dangling-file54
'

test_expect_success 'allow O_RDONLY' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -- $prog file0 rdonly
'

test_expect_success ATTACH 'attach & allow O_RDONLY' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog file0 rdonly
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

test_expect_success SYMLINKS 'allow O_RDONLY for symbolic link' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file39 rdonly
'

test_expect_success ATTACH,SYMLINKS 'attach & allow O_RDONLY for symbolic link' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog symlink-file40 rdonly
    ) &
    pandora -m core/sandbox/path:1 -p $!
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'allow O_RDONLY for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        ln -sf "$f" symlink0-outside &&
        pandora \
            -EPANDORA_TEST_SUCCESS=1 \
            -m core/sandbox/path:1 \
            -- $prog symlink0-outside rdonly
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & allow O_RDONLY for symbolic link outside' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog symlink1-outside rdonly
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    ln -sf "$f" symlink1-outside &&
    pandora -m core/sandbox/path:1 -p $pid
'

test_expect_success 'deny O_RDONLY|O_CREAT' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file1-non-existant rdonly-creat &&
    test_path_is_missing file1-non-existant
'

test_expect_success ATTACH 'attach & deny O_RDONLY|O_CREAT' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file2-non-existant rdonly-creat
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing file2-non-existant
'

test_expect_success SYMLINKS 'deny O_RDONLY|O_CREAT for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file41 rdonly-creat &&
    test_path_is_missing file41-non-existant
'

test_expect_success ATTACH,SYMLINKS 'attach & deny O_RDONLY|O_CREAT for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-file42 rdonly-creat
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing file42-non-existant
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny O_RDONLY|O_CREAT for symbolic link outside' '
    (
        f="$(mkstemp --dry-run)"
        test -n "$f" &&
        ln -sf "$f" symlink2-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink2-outside rdonly-creat &&
        test_path_is_missing "$f"
    )
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & deny O_RDONLY|O_CREAT for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink3-outside rdonly-creat
    ) &
    pid=$!
    f="$(mkstemp --dry-run)"
    test -n "$f" &&
    ln -sf "$f" symlink3-outside &&
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $pid &&
    test_path_is_missing "$f"
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file3-non-existant rdonly-creat-excl &&
    test_path_is_missing file3-non-existant
'

test_expect_success ATTACH 'attach & deny O_RDONLY|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file4-non-existant rdonly-creat-excl
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing file4-non-existant
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL for existing file' '
    test_must_violate pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -- $prog file5 rdonly-creat-excl
'

test_expect_success ATTACH 'attach & deny O_RDONLY|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog file6 rdonly-creat-excl
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $!
'

test_expect_success SYMLINKS 'deny O_RDONLY|O_CREAT|O_EXCL for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file43 rdonly-creat-excl &&
    test_path_is_missing file43-non-existant
'

test_expect_success ATTACH,SYMLINKS 'attach & deny O_RDONLY|O_CREAT|O_EXCL for symbolic link' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog symlink-file44 rdonly-creat-excl
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing file44-non-existant
'

test_expect_success 'deny O_WRONLY' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file7 wronly "3" &&
    test_path_is_empty file7
'

test_expect_success ATTACH 'attach & deny O_WRONLY' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file8 wronly "3"
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_empty file8
'

test_expect_success 'deny O_WRONLY for non-existant file' '
    test_must_violate pandora \
        -EPANDORA_TEST_ENOENT=1 \
        -m core/sandbox/path:1 \
        -- $prog file47-non-existant wronly &&
    test_path_is_missing file47-non-existant
'

test_expect_success 'attach & deny O_WRONLY for non-existant file' '
    (
        PANDORA_TEST_ENOENT=1
        export PANDORA_TEST_ENOENT
        sleep 1
        $prog file48-non-existant wronly
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing file48-non-existant
'

test_expect_success SYMLINKS 'deny O_WRONLY for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file45 wronly "3" &&
    test_path_is_empty file45-non-existant
'

test_expect_success ATTACH,SYMLINKS 'attach & deny O_WRONLY for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-file46 wronly "3"
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_empty file46
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny O_WRONLY for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        ln -sf "$f" symlink4-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink4-outside wronly "3" &&
        test_path_is_empty "$f"
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'attach & deny O_WRONLY for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink5-outside wronly "3"
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    ln -sf "$f" symlink5-outside &&
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $pid &&
    test_path_is_empty "$f"
'

test_expect_success 'deny O_WRONLY|O_CREAT' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file9-non-existant wronly-creat &&
    test_path_is_missing file9-non-existant
'

test_expect_success ATTACH 'attach & deny O_WRONLY|O_CREAT' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file10-non-existant wronly-creat
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing file10-non-existant
'

test_expect_success 'deny O_WRONLY|O_CREAT for existing file' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file49 wronly-creat "3" &&
    test_path_is_empty file49
'

test_expect_success ATTACH 'attach & deny O_WRONLY|O_CREAT for existing file' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file50 wronly-creat "3"
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_empty file50
'

test_expect_success SYMLINKS 'deny O_WRONLY|O_CREAT for symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-file51 wronly-creat "3" &&
    test_path_is_empty file51
'

test_expect_success ATTACH,SYMLINKS 'attach & deny O_WRONLY|O_CREAT for symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-file52 wronly-creat "3"
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_empty file52
'

test_expect_success SYMLINKS 'deny O_WRONLY|O_CREAT for dangling symbolic link' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog symlink-dangling-file53 wronly-creat "3" &&
    test_path_is_missing file53-non-existant
'

test_expect_success ATTACH,SYMLINKS 'attach & deny O_WRONLY|O_CREAT for dangling symbolic link' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink-dangling-file54 wronly-creat "3"
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing file54-non-existant
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny O_WRONLY|O_CREAT for symbolic link outside' '
    (
        f="$(mkstemp)"
        test -n "$f" &&
        ln -sf "$f" symlink6-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink6-outside wronly-creat "3" &&
        test_path_is_empty "$f"
    ) || return 1
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'deny O_WRONLY|O_CREAT for symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink7-outside wronly-creat "3"
    ) &
    pid=$!
    f="$(mkstemp)"
    test -n "$f" &&
    ln -sf "$f" symlink7-outside &&
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $pid &&
    test_path_is_empty "$f"
'

# FIXME: Why doesn't this work outside of a subshell?
test_expect_success MKTEMP,SYMLINKS 'deny O_WRONLY|O_CREAT for dangling symbolic link outside' '
    (
        f="$(mkstemp --dry-run)"
        test -n "$f" &&
        ln -sf "$f" symlink8-outside &&
        test_must_violate pandora \
            -EPANDORA_TEST_EPERM=1 \
            -m core/sandbox/path:1 \
            -m "allow/path:$HOME_ABSOLUTE/**" \
            -- $prog symlink8-outside wronly-creat "3" &&
        test_path_is_missing "$f"
    )
'

test_expect_success ATTACH,MKTEMP,SYMLINKS 'deny O_WRONLY|O_CREAT for dangling symbolic link outside' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog symlink9-outside wronly-creat "3"
    ) &
    pid=$!
    f="$(mkstemp --dry-run)"
    test -n "$f" &&
    ln -sf "$f" symlink9-outside &&
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/**" \
        -p $pid &&
    test_path_is_missing "$f"
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file11-non-existant wronly-creat-excl &&
    test_path_is_missing file11-non-existant
'

test_expect_success ATTACH 'deny O_WRONLY|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file12-non-existant wronly-creat-excl
    ) &
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -p $! &&
    test_path_is_missing file12-non-existant
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL for existing file' '
    test_must_violate pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -- $prog file13 wronly-creat-excl "3" &&
    test_path_is_empty file13
'

test_expect_success ATTACH 'attach & deny O_WRONLY|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog file14 wronly-creat-excl "3"
    ) &
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -p $! &&
    test_path_is_empty file14
'

test_expect_success 'allow O_WRONLY' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -- $prog file15 wronly "3" &&
    test_path_is_non_empty file15
'

test_expect_success ATTACH 'attach & allow O_WRONLY' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog file16 wronly "3"
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -p $! &&
    test_path_is_non_empty file16
'

test_expect_success 'allow O_WRONLY|O_CREAT' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -- $prog file17-non-existant wronly-creat &&
    test_path_is_file file17-non-existant
'

test_expect_success ATTACH 'attach & allow O_WRONLY|O_CREAT' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog file18-non-existant wronly-creat
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -p $! &&
    test_path_is_file file18-non-existant
'

test_expect_success 'allow O_WRONLY|O_CREAT|O_EXCL' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        $prog file19-non-existant wronly-creat-excl &&
    test_path_is_file file19-non-existant
'

test_expect_success ATTACH 'allow O_WRONLY|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog file20-non-existant wronly-creat-excl
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -p $! &&
    test_path_is_file file20-non-existant
'

test_expect_success 'allow O_WRONLY|O_CREAT|O_EXCL for existing file' '
    pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -- $prog file21 wronly-creat-excl
'

test_expect_success ATTACH 'allow O_WRONLY|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog file22 wronly-creat-excl
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -p $!
'

test_expect_success 'deny O_RDWR' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file23 rdwr "3" &&
    test_path_is_empty file23
'

test_expect_success ATTACH 'attach & deny O_RDWR' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file24 rdwr "3"
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_empty file8
'


test_expect_success 'deny O_RDWR|O_CREAT' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file25-non-existant rdwr-creat &&
    test_path_is_missing file25-non-existant
'

test_expect_success ATTACH 'attach & deny O_RDWR|O_CREAT' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file26-non-existant rdwr-creat
    ) &
    test_must_violate pandora -m core/sandbox/path:1 -p $! &&
    test_path_is_missing file26-non-existant
'


test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL' '
    test_must_violate pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox/path:1 \
        -- $prog file27-non-existant rdwr-creat-excl &&
    test_path_is_missing file27-non-existant
'

test_expect_success ATTACH 'deny O_RDWR|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $prog file28-non-existant rdwr-creat-excl
    ) &
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -p $! &&
    test_path_is_missing file28-non-existant
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL for existing file' '
    test_must_violate pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -- $prog file29 rdwr-creat-excl "3" &&
    test_path_is_empty file29
'

test_expect_success ATTACH 'attach & deny O_RDWR|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog file30 rdwr-creat-excl "3"
    ) &
    test_must_violate pandora \
        -m core/sandbox/path:1 \
        -p $! &&
    test_path_is_empty file30
'

test_expect_success 'allow O_RDWR' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -- $prog file31 rdwr "3" &&
    test_path_is_non_empty file31
'

test_expect_success ATTACH 'attach & allow O_RDWR' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog file32 rdwr "3"
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -p $! &&
    test_path_is_non_empty file32
'

test_expect_success 'allow O_RDWR|O_CREAT' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -- $prog file33-non-existant rdwr-creat &&
    test_path_is_file file33-non-existant
'

test_expect_success ATTACH 'attach & allow O_RDWR|O_CREAT' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog file34-non-existant rdwr-creat
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -p $! &&
    test_path_is_file file34-non-existant
'

test_expect_success 'allow O_RDWR|O_CREAT|O_EXCL' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        $prog file35-non-existant rdwr-creat-excl &&
    test_path_is_file file35-non-existant
'

test_expect_success ATTACH 'allow O_RDWR|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $prog file36-non-existant rdwr-creat-excl
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -p $! &&
    test_path_is_file file36-non-existant
'

test_expect_success 'allow O_RDWR|O_CREAT|O_EXCL for existing file' '
    pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -- $prog file37 rdwr-creat-excl
'

test_expect_success ATTACH 'allow O_RDWR|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $prog file38 rdwr-creat-excl
    ) &
    pandora \
        -m core/sandbox/path:1 \
        -m "allow/path:$HOME_ABSOLUTE/*" \
        -p $!
'

test_done
