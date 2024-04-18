#! /usr/bin/env bash

set -euo pipefail

HERE=$(dirname "$BASH_SOURCE")

if [ $# != 0 ]; then
    echo 'You must not pass any arguments'
    exit -1
fi

FLAGS_ERR="-Werror -Wextra -Wall -pedantic"
FLAGS_LIB="-lseccomp" # adding `-static` makes it so that we can't use `-lseccomp`
FLAGS_OPT="-Ofast"

gcc $FLAGS_ERR $FLAGS_OPT -o "$HERE/sandbox_both" "$HERE/sandbox_both.c" $FLAGS_LIB
# `FLAGS_LIB` has to go last, otherwise this won't work on ubuntu
