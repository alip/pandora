#!/bin/sh
# vim: set sw=4 et ts=4 sts=4 tw=80 :
# Copyright 2010 Ali Polatel <alip@exherbo.org>
# Distributed under the terms of the GNU General Public License v2

test_description='sandbox open(2)'
. ./test-lib.sh

f=./arnold.layne
cwd="$(readlink -f .)"
startup() {
    umask 022
    touch $f || error "touch $f"
}
cleanup() {
    rm -f $f
}
startup
trap 'cleanup' EXIT

#
# O_RDONLY
#

say 't003-open-allow-rdonly'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "rdonly" ""
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-allow-rdonly-attach'
(
    sleep 1
    ./t003_open $f "rdonly" ""
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
fi

rm -f $f || error "rm:$f"

say 't003-open-deny-rdonly-creat'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "rdonly-creat" ""
ret=$?
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

say 't003-open-deny-rdonly-creat-attach'
(
    sleep 1
    ./t003_open $f "rdonly-creat" ""
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
ret=$?
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

say 't003-open-deny-rdonly-creat-excl'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "rdonly-creat-excl" ""
ret=$?
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

say 't003-open-deny-rdonly-creat-excl-attach'
(
    sleep 1
    ./t003_open $f "rdonly-creat-excl" ""
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
ret=$?
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

startup

say 't003-open-deny-rdonly-creat-excl-existing'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "rdonly-creat-excl" "" 1
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-deny-rdonly-creat-excl-existing-attach'
(
    sleep 1
    ./t003_open $f "rdonly-creat-excl" "" 1
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

#
# O_WRONLY
#

say 't003-open-deny-wronly'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "wronly" "3"
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi
c=$(cat $f)
if test -n "$c"
then
    error "content:$c"
fi

say 't003-open-deny-wronly-attach'
(
    sleep 1
    ./t003_open $f "wronly" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
fi
c=$(cat $f)
if test -n "$c"
then
    error "content:$c"
fi

rm -f $f || error "rm:$?"

say 't003-open-deny-wronly-creat'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "wronly-creat" "3"
ret=$?
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

say 't003-open-deny-wronly-creat-attach'
(
    sleep 1
    ./t003_open $f "wronly-creat" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

say 't003-open-deny-wronly-creat-excl'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "wronly-creat-excl" "3"
ret=$?
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

say 't003-open-deny-wronly-creat-excl-attach'
(
    sleep 1
    ./t003_open $f "wronly-creat-excl" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

startup

say 't003-open-deny-wronly-creat-excl-existing'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "wronly-creat-excl" "3" 1
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-deny-wronly-creat-excl-existing-attach'
(
    sleep 1
    ./t003_open $f "wronly-creat-excl" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-allow-wronly'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open $f "wronly" "3"
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi
c=$(cat $f)
if test -z "$c"
then
    error "zero content"
fi

: > $f

say 't003-open-allow-wronly-attach'
(
    sleep 1
    ./t003_open $f "wronly" "3"
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
c=$(cat $f)
if test -z "$c"
then
    error "zero content"
fi

rm -f $f || error "rm:$?"

say 't003-open-allow-wronly-creat'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open $f "wronly-creat" "3"
ret=$?
if test $ret != 2
then
    error "ret:$ret"
elif ! test -e $f
then
    error "create"
fi

rm -f $f || error "rm:$?"

say 't003-open-allow-wronly-creat-attach'
(
    sleep 1
    ./t003_open $f "wronly-creat" "3"
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
elif ! test -e $f
then
    error "create"
fi

rm -f $f || error "rm:$?"

say 't003-open-allow-wronly-creat-excl'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open $f "wronly-creat-excl" "3"
ret=$?
if test $ret != 2
then
    error "ret:$ret"
elif ! test -e $f
then
    error "create"
fi

rm -f $f || error "rm:$?"

say 't003-open-allow-wronly-creat-excl-attach'
(
    sleep 1
    ./t003_open $f "wronly-creat-excl" "3"
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
elif ! test -e $f
then
    error "create"
fi

startup

say 't003-open-allow-wronly-creat-excl-existing'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open $f "wronly-creat-excl" "3" 1
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-allow-wronly-creat-excl-existing-attach'
(
    sleep 1
    ./t003_open $f "wronly-creat-excl" "3" 1
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    -p $pid
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

#
# O_RDWR
#

say 't003-open-deny-rdwr'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "rdwr" "3"
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi
c=$(cat $f)
if test -n "$c"
then
    error "content:$c"
fi

say 't003-open-deny-rdwr-attach'
(
    sleep 1
    ./t003_open $f "rdwr" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
fi
c=$(cat $f)
if test -n "$c"
then
    error "content:$c"
fi

rm -f $f || error "rm:$?"

say 't003-open-deny-rdwr-creat'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "rdwr-creat" "3"
ret=$?
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

say 't003-open-deny-rdwr-creat-attach'
(
    sleep 1
    ./t003_open $f "rdwr-creat" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

say 't003-open-deny-rdwr-creat-excl'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "rdwr-creat-excl" "3"
ret=$?
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

say 't003-open-deny-rdwr-creat-excl-attach'
(
    sleep 1
    ./t003_open $f "rdwr-creat-excl" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
elif test -e $f
then
    error "create"
fi

startup

say 't003-open-deny-rdwr-creat-excl-existing'
pandora \
    -m 'core/sandbox_path:1' \
    ./t003_open $f "rdwr-creat-excl" "3" 1
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-deny-rdwr-creat-excl-existing-attach'
(
    sleep 1
    ./t003_open $f "rdwr-creat-excl" "3"
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -p $pid
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-allow-rdwr'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open $f "rdwr" "3"
ret=$?
if test $ret != 2
then
    error "ret:$ret"
fi
c=$(cat $f)
if test -z "$c"
then
    error "zero content"
fi

: > $f

say 't003-open-allow-rdwr-attach'
(
    sleep 1
    ./t003_open $f "rdwr" "3"
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
c=$(cat $f)
if test -z "$c"
then
    error "zero content"
fi

rm -f $f || error "rm:$?"

say 't003-open-allow-rdwr-creat'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open $f "rdwr-creat" "3"
ret=$?
if test $ret != 2
then
    error "ret:$ret"
elif ! test -e $f
then
    error "create"
fi

rm -f $f || error "rm:$?"

say 't003-open-allow-rdwr-creat-attach'
(
    sleep 1
    ./t003_open $f "rdwr-creat" "3"
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
elif ! test -e $f
then
    error "create"
fi

rm -f $f || error "rm:$?"

say 't003-open-allow-rdwr-creat-excl'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open $f "rdwr-creat-excl" "3"
ret=$?
if test $ret != 2
then
    error "ret:$ret"
elif ! test -e $f
then
    error "create"
fi

rm -f $f || error "rm:$?"

say 't003-open-allow-rdwr-creat-excl-attach'
(
    sleep 1
    ./t003_open $f "rdwr-creat-excl" "3"
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
elif ! test -e $f
then
    error "create"
fi

startup

say 't003-open-allow-rdwr-creat-excl-existing'
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    ./t003_open $f "rdwr-creat-excl" "3" 1
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi

say 't003-open-allow-rdwr-creat-excl-existing-attach'
(
    sleep 1
    ./t003_open $f "rdwr-creat-excl" "3" 1
) &
pid=$!
pandora \
    -m 'core/sandbox_path:1' \
    -m "allow/path:$cwd/*" \
    -p $pid
ret=$?
if test $ret != 0
then
    error "ret:$ret"
fi
