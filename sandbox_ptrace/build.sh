#! /usr/bin/env bash

set -euo pipefail

HERE=$(dirname "$BASH_SOURCE")

gcc -Werror -Wextra -Wall -pedantic -static -Ofast -o "$HERE/sandbox_ptrace" "$HERE/sandbox_ptrace.c"
