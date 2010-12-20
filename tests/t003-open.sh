#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox open(2)'
. ./test-lib.sh

f='./arnold.layne'
cwd="$(readlink -f .)"
umask 022
touch "$f" || error "touch $f"
cleanup() {
    rm -f "$f"
}
trap 'cleanup' EXIT

say 't003-open-allow-rdonly'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open "$f" "rdonly" ""
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-allow-rdonly-attach'
(
    sleep 1
    ./t003_open "$f" "rdonly" ""
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-deny-wronly'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open "$f" "wronly" "3"
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi
c=$(cat "$f")
if test -n "$c"
then
    error "content:$c"
fi

say 't003-open-deny-wronly-attach'
(
    sleep 1
    ./t003_open "$f" "wronly" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
fi
c=$(cat "$f")
if test -n "$c"
then
    error "content:$c"
fi

say 't003-open-deny-rdwr'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open "$f" "rdwr" "3"
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi
c=$(cat "$f")
if test -n "$c"
then
    error "content:$c"
fi

say 't003-open-deny-rdwr-attach'
(
    sleep 1
    ./t003_open "$f" "rdwr" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
fi
c=$(cat "$f")
if test -n "$c"
then
    error "content:$c"
fi

say 't003-open-wronly-allow'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open "$f" "wronly" "3"
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi
c=$(cat "$f")
if test -z "$c"
then
    error "zero content"
fi

: > "$f"

say 't003-open-wronly-allow-attach'
(
    sleep 1
    ./t003_open "$f" "wronly" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    -p $pid
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi
c=$(cat "$f")
if test -z "$c"
then
    error "zero content"
fi

: > "$f"

say 't003-open-rdwr-allow'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open "$f" "rdwr" "3"
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi
c=$(cat "$f")
if test -z "$c"
then
    error "zero content"
fi

: > "$f"

say 't003-open-rdwr-allow-attach'
(
    sleep 1
    ./t003_open "$f" "rdwr" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    -p $pid
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi
c=$(cat "$f")
if test -z "$c"
then
    error "zero content"
fi
