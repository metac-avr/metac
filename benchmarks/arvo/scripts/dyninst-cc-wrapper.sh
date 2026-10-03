#!/bin/bash
# dyninst-cc-wrapper.sh — compiler invocation logger for the dyninst patch
# mechanism (ArvoValidator.dyninst_patch()). Symlinked as `clang` and
# `clang++` in the same directory as the real compilers (see setup_dyninst()
# in checkout.py, which renames the originals to `clang.real`/`clang++.real`
# before installing these symlinks in their place) so that
# ArvoValidator.setup()'s own real build -- which we never touch -- captures
# a full, accurate compile-invocation log for free, with no separate
# rebuild of the project needed.
#
# Unlike the older jitpatch-cc-wrapper.sh (a different, gcc-era pipeline),
# this wrapper does not strip or reroute any flags: it passes every argument
# through unchanged. Its only job is to log, then exec the real compiler --
# ArvoValidator.setup() must build with the exact same flags it always has,
# since that build IS the sanitizer-instrumented target the vulnerability
# test runs against.
#
# Log format matches jitpatch-cc-wrapper.sh's (dyninst_patch()'s
# _parse_cc_log() reads either the same way): one block per invocation,
# serialized with flock since a parallel (-j N) build runs many wrapper
# instances concurrently and a plain multi-line append is not atomic across
# processes.
set -euo pipefail

self_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
self_name="$(basename "$0")"
REAL="${self_dir}/${self_name}.real"

if [[ ! -x "$REAL" ]]; then
    echo "dyninst-cc-wrapper: real compiler not found at $REAL" >&2
    exit 127
fi

LOG="${DYNINST_CC_LOG:-/opt/dyninst-tool/cc-invocations.log}"
if [[ -d "$(dirname "$LOG")" ]]; then
    block="==CC_INVOCATION==
CWD: $(pwd)
ARGV0: $0"
    for arg in "$@"; do
        block+=$'\n'"ARG: $arg"
    done
    block+=$'\n'"==END=="
    (
        flock 9
        printf '%s\n' "$block" >> "$LOG"
    ) 9>"${LOG}.lock"
fi

exec "$REAL" "$@"
