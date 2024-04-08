#! /usr/bin/env bash

set -euo pipefail

HERE=$(dirname "$BASH_SOURCE")

gcc -Werror -Wextra -Wall -pedantic -lseccomp -Ofast -o "$HERE/sandbox_both" "$HERE/sandbox_both.c"
# adding `-static` makes it so that we can't use `-lseccomp`
