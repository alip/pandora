#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox chmod(2)'
. ./test-lib.sh

f=./arnold.layne
cwd="$(readlink -f .)"
umask 022
touch $f || error "touch $f"
cleanup () {
    rm -f $f
}
trap 'cleanup' EXIT

say 't001-chmod-deny'
pandora \
    -m 'core/sandbox_path:1' \
    ./t001_chmod $f
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi
p=$(stat -c '%a' $f)
if test $p != 644
then
    error "perm:$p"
fi

say 't001-chmod-deny-attach'
(
    sleep 1
    ./t001_chmod $f
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi
p=$(stat -c '%a' $f)
if test $p != 644
then
    error "perm:$p"
fi

say 't001-chmod-deny-toggle'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    -m "disallow/path:$cwd/*" \
    ./t001_chmod $f
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi
p=$(stat -c '%a' $f)
if test $p != 644
then
    error "perm:$p"
fi

say 't001-chmod-allow'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t001_chmod $f
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi
p=$(stat -c '%s' $f)
if test $p != 0
then
    error "perm:$p"
fi

chmod 644 $f || error "chmod:$?"

say 't001-chmod-allow-attach'
(
    sleep 1
    ./t001_chmod $f
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
p=$(stat -c '%s' $f)
if test $p != 0
then
    error "perm:$p"
fi

chmod 644 $f || error "chmod:$?"

say 't001-chmod-allow-toggle'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    -m "disallow/path:$cwd/*" \
    -m "allow/path:$cwd/*" \
    ./t001_chmod $f
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi
p=$(stat -c '%s' $f)
if test $p != 0
then
    error "perm:$p"
fi
