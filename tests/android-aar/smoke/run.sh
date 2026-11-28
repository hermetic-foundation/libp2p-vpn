#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || -z $2 ]]; then
    printf 'Usage: bash run.sh SMOKE.apk ADB_SERIAL\n' >&2
    exit 2
fi
device=(adb -s "$2")
package=example.aarsmoke
if timeout 10 "${device[@]}" shell pm path "$package" >/dev/null; then
    printf 'Refusing to replace an existing installation of %s.\n' "$package" >&2
    exit 1
else
    status=$?
    if (( status != 1 )); then
        exit "$status"
    fi
fi
if timeout 90 "${device[@]}" install "$1"; then
    trap 'timeout 45 "${device[@]}" uninstall "$package"' EXIT
else
    status=$?
    printf 'Install did not report success. Check whether the test package is present:\n' >&2
    printf '  adb -s %q shell pm path %q\n' "$2" "$package" >&2
    printf 'If this run installed it, remove it before retrying:\n' >&2
    printf '  adb -s %q uninstall %q\n' "$2" "$package" >&2
    exit "$status"
fi
trap 'exit 130' INT
trap 'exit 143' TERM
result=$(timeout 45 "${device[@]}" shell am instrument -w -r "$package/.Smoke")
printf '%s\n' "$result"
grep -Fxq 'PASS Android AAR preserves peer identity across rename' <<< "$result"
grep -Fxq 'INSTRUMENTATION_CODE: -1' <<< "$result"
