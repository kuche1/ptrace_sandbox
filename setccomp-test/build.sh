#! /usr/bin/env bash

set -euo pipefail

HERE=$(dirname "$BASH_SOURCE")

gcc -Werror -Wextra -Wall -pedantic -lseccomp -Ofast -o "$HERE/sandbox_setccomp" "$HERE/sandbox_setccomp.c"
# adding `-static` makes it so that we can't use `-lseccomp`
