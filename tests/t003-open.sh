#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox open(2)'
. ./test-lib.sh

#
# TODO: Some corner cases aren't covered:
#
# - O_CREAT|O_EXCL does not resolve symbolic links

test_expect_success setup '
    touch file0 &&
    touch file1 &&
    touch file2 &&
    rm -f file3 &&
    rm -f file4 &&
    rm -f file5 &&
    rm -f file6 &&
    touch file7 &&
    touch file8 &&
    touch file9 &&
    touch file10 &&
    rm -f file11 &&
    rm -f file12 &&
    rm -f file13 &&
    rm -f file14 &&
    touch file15 &&
    touch file16 &&
    touch file17 &&
    touch file18 &&
    rm -f file19 &&
    rm -f file20 &&
    rm -f file21 &&
    rm -f file22 &&
    touch file23 &&
    touch file24 &&
    touch file25 &&
    touch file26 &&
    rm -f file27 &&
    rm -f file28 &&
    rm -f file29 &&
    rm -f file30 &&
    touch file31 &&
    touch file32 &&
    ln -sf /non/existant/file slink0
'

test_expect_success ATTACH 'deny O_RDWR|O_CREAT|O_EXCL (dangling symlink) (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open slink0 rdwr-creat-excl 0 0
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'allow O_RDONLY' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file0 rdonly 0 1
'

test_expect_success ATTACH 'allow O_RDONLY (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file0 rdonly 0 1
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'deny O_RDONLY|O_CREAT' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file666 rdonly-creat 0 0 &&
    test ! -e file666
'

test_expect_success ATTACH 'deny O_RDONLY|O_CREAT (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file667 rdonly-creat 0 0
    ) &
    pandora -m core/sandbox_path:1 -p $! &&
    test ! -e file667
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file668 rdonly-creat-excl 0 0 &&
    test ! -e file668
'

test_expect_success ATTACH 'deny O_RDONLY|O_CREAT|O_EXCL (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file669 rdonly-creat-excl 0 0
    ) &
    pandora -m core/sandbox_path:1 -p $! &&
    test ! -e file669
'

test_expect_success 'deny O_RDONLY|O_CREAT|O_EXCL (EEXIST)' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file668 rdonly-creat-excl 0 0
'

test_expect_success ATTACH 'deny O_RDONLY|O_CREAT|O_EXCL (EEXIST) (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file669 rdonly-creat-excl 0 0
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'deny O_WRONLY' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file1 wronly 0 0 "3" &&
    test -z "$(cat file1)"
'

test_expect_success ATTACH 'deny O_WRONLY (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file2 wronly 0 0 "3"
    ) &
    pandora -m core/sandbox_path:1 -p $! &&
    test -z "$(cat file2)"
'

test_expect_success 'deny O_WRONLY|O_CREAT' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file3 wronly-creat 0 0 &&
    test ! -e file3
'

test_expect_success ATTACH 'deny O_WRONLY|O_CREAT (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file4 wronly-creat 0 0
    ) &
    pandora -m core/sandbox_path:1 -p $! &&
    test ! -e file4
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file5 wronly-creat-excl 0 0 &&
    test ! -e file5
'

test_expect_success ATTACH 'deny O_WRONLY|O_CREAT|O_EXCL (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file6 wronly-creat-excl 0 0
    ) &
    pandora -m core/sandbox_path:1 -p $! &&
    test ! -e file6
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL (EEXIST)' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file7 wronly-creat-excl 1 0
'

test_expect_success ATTACH 'deny O_WRONLY|O_CREAT|O_EXCL (EEXIST) (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file8 wronly-creat-excl 1 0
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'allow O_WRONLY' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" $TEST_DIRECTORY/t003_open file9 wronly 0 1 "3" &&
    test -n $(cat file9)
'

test_expect_success ATTACH 'allow O_WRONLY (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file10 wronly 0 1 "3"
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $! &&
    test -n $(cat file10)
'

test_expect_success 'allow O_WRONLY|O_CREAT' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" $TEST_DIRECTORY/t003_open file11 wronly-creat 0 1 "3" &&
    test -e file11
'

test_expect_success ATTACH 'allow O_WRONLY|O_CREAT (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file12 wronly-creat 0 1 "3"
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $! &&
    test -e file12
'

test_expect_success 'allow O_WRONLY|O_CREAT|O_EXCL' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" $TEST_DIRECTORY/t003_open file13 wronly-creat-excl 0 1 "3" &&
    test -e file13
'

test_expect_success ATTACH 'allow O_WRONLY|O_CREAT|O_EXCL (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file14 wronly-creat-excl 0 1 "3"
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $! &&
    test -e file14
'

test_expect_success 'allow O_WRONLY|O_CREAT|O_EXCL (EEXIST)' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" $TEST_DIRECTORY/t003_open file15 wronly-creat-excl 1 0 "3"
'

test_expect_success ATTACH 'allow O_WRONLY|O_CREAT|O_EXCL (EEXIST) (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file16 wronly-creat-excl 1 0 "3"
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $!
'

test_expect_success 'deny O_RDWR' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file17 rdwr 0 0 "3" &&
    test -z "$(cat file17)"
'

test_expect_success ATTACH 'deny O_RDWR (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file18 rdwr 0 0 "3"
    ) &
    pandora -m core/sandbox_path:1 -p $! &&
    test -z "$(cat file18)"
'

test_expect_success 'deny O_RDWR|O_CREAT' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file19 rdwr-creat 0 0 &&
    test ! -e file19
'

test_expect_success ATTACH 'deny O_RDWR|O_CREAT (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file20 rdwr-creat 0 0
    ) &
    pandora -m core/sandbox_path:1 -p $! &&
    test ! -e file20
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file21 rdwr-creat-excl 0 0 &&
    test ! -e file21
'

test_expect_success ATTACH 'deny O_RDWR|O_CREAT|O_EXCL (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file22 rdwr-creat-excl 0 0
    ) &
    pandora -m core/sandbox_path:1 -p $! &&
    test ! -e file22
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL (EEXIST)' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open file23 rdwr-creat-excl 1 0
'

test_expect_success ATTACH 'deny O_RDWR|O_CREAT|O_EXCL (EEXIST) (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file24 rdwr-creat-excl 1 0
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'allow O_RDWR' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" $TEST_DIRECTORY/t003_open file25 rdwr 0 1 "3" &&
    test -n $(cat file25)
'

test_expect_success ATTACH 'allow O_RDWR (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file26 rdwr 0 1 "3"
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $! &&
    test -n $(cat file26)
'

test_expect_success 'allow O_RDWR|O_CREAT' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" $TEST_DIRECTORY/t003_open file27 rdwr-creat 0 1 "3" &&
    test -e file27
'

test_expect_success ATTACH 'allow O_RDWR|O_CREAT (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file28 rdwr-creat 0 1 "3"
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $! &&
    test -e file28
'

test_expect_success 'allow O_RDWR|O_CREAT|O_EXCL' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" $TEST_DIRECTORY/t003_open file29 rdwr-creat-excl 0 1 "3" &&
    test -e file29
'

test_expect_success ATTACH 'allow O_RDWR|O_CREAT|O_EXCL (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file30 rdwr-creat-excl 0 1 "3"
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $! &&
    test -e file30
'

test_expect_success 'allow O_RDWR|O_CREAT|O_EXCL (EEXIST)' '
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" $TEST_DIRECTORY/t003_open file31 rdwr-creat-excl 1 0 "3"
'

test_expect_success ATTACH 'allow O_RDWR|O_CREAT|O_EXCL (EEXIST) (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open file32 rdwr-creat-excl 1 0 "3"
    ) &
    pandora -m core/sandbox_path:1 -m "allow/path:$TEST_DIRECTORY_ABSOLUTE/*" -p $!
'

test_expect_success 'deny O_WRONLY|O_CREAT|O_EXCL (dangling symlink)' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open slink0 wronly-creat-excl 0 0
'

test_expect_success ATTACH 'deny O_WRONLY|O_CREAT|O_EXCL (dangling symlink) (attach)' '
    (
        sleep 1
        $TEST_DIRECTORY/t003_open slink0 wronly-creat-excl 0 0
    ) &
    pandora -m core/sandbox_path:1 -p $!
'

test_expect_success 'deny O_RDWR|O_CREAT|O_EXCL (dangling symlink)' '
    pandora -m core/sandbox_path:1 $TEST_DIRECTORY/t003_open slink0 rdwr-creat-excl 0 0
'

test_expect_success cleanup '
    rm -f file0 &&
    rm -f file1 &&
    rm -f file2 &&
    rm -f file3 &&
    rm -f file4 &&
    rm -f file5 &&
    rm -f file6 &&
    rm -f file7 &&
    rm -f file8 &&
    rm -f file9 &&
    rm -f file10 &&
    rm -f file11 &&
    rm -f file12 &&
    rm -f file13 &&
    rm -f file14 &&
    rm -f file15 &&
    rm -f file16 &&
    rm -f file17 &&
    rm -f file18 &&
    rm -f file19 &&
    rm -f file20 &&
    rm -f file21 &&
    rm -f file22 &&
    rm -f file23 &&
    rm -f file24 &&
    rm -f file25&&
    rm -f file26 &&
    rm -f file27 &&
    rm -f file28 &&
    rm -f file29 &&
    rm -f file30 &&
    rm -f file31 &&
    rm -f file32 &&
    unlink slink0
'

test_done
