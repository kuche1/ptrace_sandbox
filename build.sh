#! /usr/bin/env bash

set -euo pipefail

HERE=$(dirname "$BASH_SOURCE")

gcc -Werror -Wextra -Wall -pedantic -static -o "$HERE/sandbox" "$HERE/sandbox.c"
