#!/usr/bin/env bash

session_test_cleanup() {
    local test_status=$?
    local cleanup_status=0

    trap - EXIT
    python3 "$SECDAT_SESSION_TEST_CLEANUP_SCRIPT" \
        "$SECDAT_SESSION_TEST_ROOT" || cleanup_status=$?
    if test "$cleanup_status" -eq 0; then
        rm -rf -- "$SECDAT_SESSION_TEST_ROOT"
    else
        printf 'FAIL: preserving session test root after cleanup failure: %s\n' \
            "$SECDAT_SESSION_TEST_ROOT" >&2
    fi
    if test "$test_status" -ne 0; then
        exit "$test_status"
    fi
    exit "$cleanup_status"
}

secdat_session_test_cleanup_install() {
    local cleanup_source_dir

    cleanup_source_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    export SECDAT_SESSION_TEST_ROOT="$1"
    export SECDAT_SESSION_TEST_CLEANUP_SCRIPT="$cleanup_source_dir/session_agent_cleanup.py"
    trap session_test_cleanup EXIT
}
