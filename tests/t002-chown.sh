#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chown(2)'
. ./test-lib.sh

f='./arnold.layne'
cwd="$(readlink -f .)"
umask 022
touch "$f" || error "touch $f"
cleanup () {
    rm -f "$f"
}
trap 'cleanup' EXIT

say 't002-chown-deny'
pandora \
    -m 'core/sandbox_path:1' \
    ./t002_chown $f
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

say 't002-chown-deny-toggle'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    -m "disallow/path:$cwd/*" \
    ./t002_chown $f
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

say 't002-chown-allow'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t002_chown $f
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi

say 't002-chown-allow-toggle'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    -m "disallow/path:$cwd/*" \
    -m "allow/path:$cwd/*" \
    ./t002_chown $f
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi
