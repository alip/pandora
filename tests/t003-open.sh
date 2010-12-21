#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox open(2)'
. ./test-lib.sh

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
    rm -f file9 &&
    rm -f file10 &&
    rm -f file11 &&
    rm -f file12 &&
    touch file13 &&
    touch file14 &&
    touch file15 &&
    touch file16 &&
    rm -f file17 &&
    rm -f file18 &&
    rm -f file19 &&
    rm -f file20 &&
    touch file21 &&
    touch file22 &&
    touch file23 &&
    touch file24 &&
    rm -f file25 &&
    rm -f file26 &&
    rm -f file27 &&
    rm -f file28 &&
    touch file29 &&
    touch file30 &&
    touch file31 &&
    touch file32 &&
    rm -f file33 &&
    rm -f file34 &&
    rm -f file35 &&
    rm -f file36 &&
    touch file37 &&
    touch file38
'

test_expect_success SYMLINKS setup-symlinks '
    ln -sf /non/existant/file symlink-dangling
'

test_expect_success 'allow O_RDONLY' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file0 rdonly
'

test_expect_success ATTACH 'attach & allow O_RDONLY' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file0 rdonly
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'deny O_RDONLY|O_CREAT' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file1-non-existant rdonly-creat
    test $? = 128 &&
    test ! -e file1-non-existant
'

test_expect_success ATTACH 'deny O_RDONLY|O_CREAT' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file2-non-existant rdonly-creat
    ) &
    pandora -m core/sandbox_path:1 -p $!
    test $? = 128 &&
    test ! -e file2-non-existant
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file3-non-existant rdonly-creat-excl
    test $? = 128 &&
    test ! -e file3-non-existant
'

test_expect_success ATTACH 'deny O_RDONLY|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file4-non-existant rdonly-creat-excl
    ) &
    pandora -m core/sandbox_path:1 -p $!
    test $? = 128 &&
    test ! -e file4-non-existant
'

test_expect_code 128 'deny O_RDONLY|O_CREAT|O_EXCL for existing file' '
    pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file5 rdonly-creat-excl
'

test_expect_code ATTACH 128 'attach & deny O_RDONLY|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file6 rdonly-creat-excl
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'deny O_WRONLY' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file7 wronly "3"
    test $? = 128 &&
    test -z "$(cat file7)"
'

test_expect_success ATTACH 'attach & deny O_WRONLY' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file8 wronly "3"
    ) &
    pandora -m core/sandbox_path:1 -p $!
    test $? = 128 &&
    test -z "$(cat file8)"
'


test_expect_success 'deny O_WRONLY|O_CREAT' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file9 wronly-creat
    test $? = 128 &&
    test ! -e file9
'

test_expect_success ATTACH 'attach & deny O_WRONLY|O_CREAT' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file10 wronly-creat
    ) &
    pandora -m core/sandbox_path:1 -p $!
    test $? = 128 &&
    test ! -e file10
'


test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file11 wronly-creat-excl
    test $? = 128 &&
    test ! -e file11
'

test_expect_success ATTACH 'deny O_WRONLY|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file12 wronly-creat-excl
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -p $!
    test $? = 128 &&
    test ! -e file12
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL for existing file' '
    pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file13 wronly-creat-excl "3"
    test $? = 128 &&
    test -z "$(cat file13)"
'

test_expect_success ATTACH 'attach & deny O_WRONLY|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file14 wronly-creat-excl "3"
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -p $!
    test $? = 128 &&
    test -z "$(cat file14)"
'

test_expect_success 'allow O_WRONLY' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file15 wronly "3" &&
    test -n "$(cat file15)"
'

test_expect_success ATTACH 'attach & allow O_WRONLY' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file16 wronly "3"
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -p $! &&
    test -n "$(cat file16)"
'

test_expect_success 'allow O_WRONLY|O_CREAT' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file17 wronly-creat &&
    test -e file17
'

test_expect_success ATTACH 'attach & allow O_WRONLY|O_CREAT' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file18 wronly-creat
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -p $! &&
    test -e file18
'

test_expect_success 'allow O_WRONLY|O_CREAT|O_EXCL' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        $TEST_DIRECTORY_ABSOLUTE/t003_open file19 wronly-creat-excl &&
    test -e file19
'

test_expect_success ATTACH 'allow O_WRONLY|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file20 wronly-creat-excl
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -p $! &&
    test -e file20
'

test_expect_success 'allow O_WRONLY|O_CREAT|O_EXCL for existing file' '
    pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file21 wronly-creat-excl
'

test_expect_success ATTACH 'allow O_WRONLY|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file22 wronly-creat-excl
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -p $!
'

test_expect_success 'deny O_RDWR' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file23 rdwr "3"
    test $? = 128 &&
    test -z "$(cat file23)"
'

test_expect_success ATTACH 'attach & deny O_RDWR' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file24 rdwr "3"
    ) &
    pandora -m core/sandbox_path:1 -p $!
    test $? = 128 &&
    test -z "$(cat file8)"
'


test_expect_success 'deny O_RDWR|O_CREAT' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file25 rdwr-creat
    test $? = 128 &&
    test ! -e file25
'

test_expect_success ATTACH 'attach & deny O_RDWR|O_CREAT' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file26 rdwr-creat
    ) &
    pandora -m core/sandbox_path:1 -p $!
    test $? = 128 &&
    test ! -e file26
'


test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL' '
    pandora \
        -EPANDORA_TEST_EPERM=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file27 rdwr-creat-excl
    test $? = 128 &&
    test ! -e file27
'

test_expect_success ATTACH 'deny O_RDWR|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_EPERM=1
        export PANDORA_TEST_EPERM
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file28 rdwr-creat-excl
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -p $!
    test $? = 128 &&
    test ! -e file28
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL for existing file' '
    pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox_path:1 \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file29 rdwr-creat-excl "3"
    test $? = 128 &&
    test -z "$(cat file29)"
'

test_expect_success ATTACH 'attach & deny O_RDWR|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file30 rdwr-creat-excl "3"
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -p $!
    test $? = 128 &&
    test -z "$(cat file30)"
'

test_expect_success 'allow O_RDWR' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file31 rdwr "3" &&
    test -n "$(cat file31)"
'

test_expect_success ATTACH 'attach & allow O_RDWR' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file32 rdwr "3"
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -p $! &&
    test -n "$(cat file32)"
'

test_expect_success 'allow O_RDWR|O_CREAT' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file33 rdwr-creat &&
    test -e file33
'

test_expect_success ATTACH 'attach & allow O_RDWR|O_CREAT' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file34 rdwr-creat
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -p $! &&
    test -e file34
'

test_expect_success 'allow O_RDWR|O_CREAT|O_EXCL' '
    pandora \
        -EPANDORA_TEST_SUCCESS=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        $TEST_DIRECTORY_ABSOLUTE/t003_open file35 rdwr-creat-excl &&
    test -e file35
'

test_expect_success ATTACH 'allow O_RDWR|O_CREAT|O_EXCL' '
    (
        PANDORA_TEST_SUCCESS=1
        export PANDORA_TEST_SUCCESS
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file36 rdwr-creat-excl
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -p $! &&
    test -e file36
'

test_expect_success 'allow O_RDWR|O_CREAT|O_EXCL for existing file' '
    pandora \
        -EPANDORA_TEST_EEXIST=1 \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -- $TEST_DIRECTORY_ABSOLUTE/t003_open file37 rdwr-creat-excl
'

test_expect_success ATTACH 'allow O_RDWR|O_CREAT|O_EXCL for existing file' '
    (
        PANDORA_TEST_EEXIST=1
        export PANDORA_TEST_EEXIST
        sleep 1
        $TEST_DIRECTORY_ABSOLUTE/t003_open file38 rdwr-creat-excl
    ) &
    pandora \
        -m core/sandbox_path:1 \
        -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" \
        -p $!
'

test_done
