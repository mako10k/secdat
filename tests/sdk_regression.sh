#!/usr/bin/env bash

set -euo pipefail

bin_path="${1:-./src/secdat}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

build_root="$(cd "$(dirname "$bin_path")/.." && pwd)"
shared_library_path="${2-$build_root/src/.libs/libsecdat.so}"
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source_root="$(cd "$script_dir/.." && pwd)"
work_root="$(mktemp -d)"
# shellcheck source=tests/session_test_cleanup.sh
. "$script_dir/session_test_cleanup.sh"
secdat_session_test_cleanup_install "$work_root"

export XDG_RUNTIME_DIR="$work_root/runtime"
export XDG_DATA_HOME="$work_root/data"
export LC_ALL=C
export LANGUAGE=C
export SECDAT_MASTER_KEY="sdk-regression-master-key"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_DATA_HOME"

pkg_config_bin="${PKG_CONFIG:-pkg-config}"
if ! sdk_static_link_flags_text=$(
    PKG_CONFIG_PATH="$build_root${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}" \
        "$pkg_config_bin" --static --libs libsecdat
); then
    fail "pkg-config could not resolve the static libsecdat link contract"
fi
read -r -a sdk_static_link_flags <<<"$sdk_static_link_flags_text"
sdk_private_link_flags_text=$(sed -n 's/^Libs\.private:[[:space:]]*//p' "$build_root/libsecdat.pc")
if test -z "$sdk_private_link_flags_text"; then
    fail "generated libsecdat.pc does not declare the private static link closure"
fi

root_domain="$work_root/root"
child_domain="$root_domain/child"
orphaned_child_domain="$root_domain/orphaned-child"
refresh_domain="$work_root/refresh"
ephemeral_expiry_race_domain="$work_root/ephemeral-expiry-race"
long_role="$(printf '%*s' 5000 '' | tr ' ' r)"
mkdir -p "$root_domain" "$child_domain" "$orphaned_child_domain" "$refresh_domain" "$ephemeral_expiry_race_domain"

run_secdat() {
    local stdout_path="$work_root/stdout"
    local stderr_path="$work_root/stderr"

    if ! "$bin_path" "$@" >"$stdout_path" 2>"$stderr_path"; then
        printf 'stdout:\n%s\nstderr:\n%s\n' "$(cat "$stdout_path")" "$(cat "$stderr_path")" >&2
        fail "secdat command failed: $*"
    fi
    if test -s "$stderr_path"; then
        printf 'stderr:\n%s\n' "$(cat "$stderr_path")" >&2
        fail "unexpected stderr from secdat command: $*"
    fi
}

run_secdat --dir "$root_domain" domain create
run_secdat --dir "$child_domain" domain create
run_secdat --dir "$orphaned_child_domain" domain create
run_secdat --dir "$refresh_domain" domain create
run_secdat --dir "$ephemeral_expiry_race_domain" domain create
run_secdat --dir "$root_domain" store create team
run_secdat --dir "$root_domain" store create enumeration
run_secdat --dir "$ephemeral_expiry_race_domain" store create team
run_secdat --dir "$root_domain" --store team set API_TOKEN --value sdk-secret-value
run_secdat --dir "$root_domain" --store team set PUBLIC_URL --unsafe --value public-secret-value
run_secdat --dir "$root_domain" --store team set BULK_TOKEN --bulk-select include --value bulk-secret-value
run_secdat --dir "$root_domain" --store team set LONG_PRIMARY --value long-primary-value
run_secdat --dir "$root_domain" --store team set LONG_SECONDARY --value long-secondary-value
run_secdat --dir "$refresh_domain" set CONSUMER_TOKEN --value consumer-token
run_secdat --dir "$root_domain" --store team relation set sdk-refresh \
    --member token=API_TOKEN \
    --member bulk_token=BULK_TOKEN \
    --member account=PUBLIC_URL \
    --security combination-sensitive
run_secdat --dir "$refresh_domain" relation set sdk-cross-refresh \
    --member "token=$root_domain/API_TOKEN:team" \
    --member refresh_token=CONSUMER_TOKEN \
    --security combination-sensitive
run_secdat --dir "$root_domain" --store team relation set sdk-long-refresh \
    --member "$long_role=LONG_PRIMARY" \
    --member secondary=LONG_SECONDARY \
    --security combination-sensitive
run_secdat --dir "$orphaned_child_domain" set ORPHANED_SDK_KEY --value orphaned-sdk-value
rmdir "$orphaned_child_domain"
run_secdat --dir "$root_domain" --store team set SDK_EPHEMERAL_RACE --value persisted-race-value
run_secdat --dir "$root_domain" --store team set SDK_PERSISTENT_SOURCE --value sdk-persistent-source-value
run_secdat --dir "$root_domain" --store team set SDK_MASKED_EPHEMERAL --value persisted-masked-value
run_secdat --dir "$child_domain" --store team mask SDK_MASKED_EPHEMERAL
run_secdat --dir "$root_domain" store migrate enumeration --to-format v2
run_secdat --dir "$root_domain" --store enumeration set SDK_HIDDEN_EPHEMERAL \
    --key-visibility unlocked \
    --value persisted-hidden-value
run_secdat --dir "$ephemeral_expiry_race_domain" --store team set SDK_EPHEMERAL_RACE --value persisted-expiry-race-value

ephemeral_unlock_stdout="$work_root/ephemeral-unlock.stdout"
ephemeral_unlock_stderr="$work_root/ephemeral-unlock.stderr"
if ! "$bin_path" --dir "$root_domain" unlock --volatile >"$ephemeral_unlock_stdout" 2>"$ephemeral_unlock_stderr"; then
    fail "failed to start SDK ephemeral test session"
fi
if ! grep -q "resolved domain: $root_domain" "$ephemeral_unlock_stderr"; then
    fail "SDK ephemeral test unlock did not report its domain"
fi
run_secdat --dir "$root_domain" --store team set --ephemeral SDK_EPHEMERAL --value sdk-ephemeral-value
run_secdat --dir "$root_domain" --store team set --ephemeral SDK_EPHEMERAL_DEST --value sdk-ephemeral-destination-value
run_secdat --dir "$root_domain" --store team set --ephemeral SDK_EPHEMERAL_RACE --value ephemeral-race-value
run_secdat --dir "$child_domain" --store team set --ephemeral SDK_MASKED_EPHEMERAL \
    --bulk-select include \
    --value ephemeral-masked-value
run_secdat --dir "$root_domain" --store enumeration set --ephemeral SDK_HIDDEN_EPHEMERAL \
    --value ephemeral-hidden-value
cat >"$work_root/sdk_ephemeral_harness.c" <<'C'
#include "secdat-sdk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

enum refusal_operation {
    REFUSAL_RM,
    REFUSAL_MV,
    REFUSAL_CP,
    REFUSAL_MASK,
    REFUSAL_UNMASK
};

struct refusal_case {
    const char *label;
    enum refusal_operation operation;
    const char *source;
    const char *destination;
};

static int run_refusal_case(
    const struct secdat_sdk_options *options,
    const struct refusal_case *test_case
)
{
    switch (test_case->operation) {
        case REFUSAL_RM:
            return secdat_sdk_rm(options, test_case->source, 0);
        case REFUSAL_MV:
            return secdat_sdk_mv(options, test_case->source, test_case->destination);
        case REFUSAL_CP:
            return secdat_sdk_cp(options, test_case->source, test_case->destination);
        case REFUSAL_MASK:
            return secdat_sdk_mask(options, test_case->source);
        case REFUSAL_UNMASK:
            return secdat_sdk_unmask(options, test_case->source);
    }
    return 0;
}

int main(int argc, char **argv)
{
    struct secdat_sdk_options options = {0};
    struct secdat_sdk_key_metadata_list keys = {0};
    const struct secdat_sdk_key_metadata *ephemeral = NULL;
    unsigned char *value = NULL;
    size_t value_length = 0;
    int unsafe_store = 0;
    size_t index;
    const struct refusal_case refusal_cases[] = {
        {"rm source", REFUSAL_RM, "SDK_EPHEMERAL", NULL},
        {"mv source", REFUSAL_MV, "SDK_EPHEMERAL", "SDK_MV_FROM_EPHEMERAL"},
        {"mv destination", REFUSAL_MV, "SDK_PERSISTENT_SOURCE", "SDK_EPHEMERAL_DEST"},
        {"cp source", REFUSAL_CP, "SDK_EPHEMERAL", "SDK_CP_FROM_EPHEMERAL"},
        {"cp destination", REFUSAL_CP, "SDK_PERSISTENT_SOURCE", "SDK_EPHEMERAL_DEST"},
        {"mask source", REFUSAL_MASK, "SDK_EPHEMERAL", NULL},
        {"unmask source", REFUSAL_UNMASK, "SDK_EPHEMERAL", NULL},
    };

    if (argc != 2) {
        fail("expected root domain path");
    }
    options.dir = argv[1];
    options.store = "team";

    if (secdat_sdk_get(&options, "SDK_EPHEMERAL", &value, &value_length, &unsafe_store) != 0
        || value_length != strlen("sdk-ephemeral-value")
        || memcmp(value, "sdk-ephemeral-value", value_length) != 0
        || unsafe_store) {
        fail("SDK get did not read the ephemeral value");
    }
    secdat_sdk_free(value);

    if (secdat_sdk_list_keys(&options, NULL, &keys) != 0) {
        fail("SDK list did not read ephemeral metadata");
    }
    for (index = 0; index < keys.count; index += 1) {
        if (strcmp(keys.items[index].key, "SDK_EPHEMERAL") == 0) {
            ephemeral = &keys.items[index];
            break;
        }
    }
    if (ephemeral == NULL
        || strcmp(ephemeral->storage_mode, "ephemeral") != 0
        || ephemeral->unsafe_store
        || strcmp(ephemeral->key_visibility, "unlocked") != 0
        || strcmp(ephemeral->value_access, "unlocked") != 0
        || strcmp(ephemeral->bulk_select, "exclude") != 0) {
        fail("SDK list returned wrong ephemeral metadata");
    }
    secdat_sdk_free(keys.items);

    if (secdat_sdk_set(
            &options,
            "SDK_EPHEMERAL",
            (const unsigned char *)"must-not-persist",
            strlen("must-not-persist"),
            0
        ) == 0) {
        fail("SDK write unexpectedly persisted over an ephemeral key");
    }
    if (secdat_sdk_write_at_preserve_attrs(
            &options,
            "SDK_EPHEMERAL",
            (const unsigned char *)"blocked",
            strlen("blocked"),
            0,
            0
        ) == 0) {
        fail("SDK atomic write unexpectedly updated an ephemeral key");
    }
    if (secdat_sdk_resize_preserve_attrs(
            &options,
            "SDK_EPHEMERAL",
            strlen("short")
        ) == 0) {
        fail("SDK atomic resize unexpectedly updated an ephemeral key");
    }
    for (index = 0; index < sizeof(refusal_cases) / sizeof(refusal_cases[0]); index += 1) {
        if (run_refusal_case(&options, &refusal_cases[index]) == 0) {
            fail(refusal_cases[index].label);
        }
    }
    if (secdat_sdk_get(&options, "SDK_EPHEMERAL", &value, &value_length, &unsafe_store) != 0
        || value_length != strlen("sdk-ephemeral-value")
        || memcmp(value, "sdk-ephemeral-value", value_length) != 0
        || unsafe_store) {
        fail("rejected SDK atomic update changed the ephemeral value");
    }
    secdat_sdk_free(value);
    if (secdat_sdk_get(&options, "SDK_EPHEMERAL_DEST", &value, &value_length, &unsafe_store) != 0
        || value_length != strlen("sdk-ephemeral-destination-value")
        || memcmp(value, "sdk-ephemeral-destination-value", value_length) != 0
        || unsafe_store) {
        fail("rejected SDK destination mutation changed the ephemeral value");
    }
    secdat_sdk_free(value);
    if (secdat_sdk_get(&options, "SDK_PERSISTENT_SOURCE", &value, &value_length, &unsafe_store) != 0
        || value_length != strlen("sdk-persistent-source-value")
        || memcmp(value, "sdk-persistent-source-value", value_length) != 0
        || unsafe_store) {
        fail("rejected SDK destination move changed the persisted source");
    }
    secdat_sdk_free(value);
    return 0;
}
C

cc -I"$source_root/src" -I"$build_root/src" "$work_root/sdk_ephemeral_harness.c" \
    -L"$build_root/src/.libs" "${sdk_static_link_flags[@]}" \
    -Wl,-rpath,"$build_root/src/.libs" \
    -o "$work_root/sdk_ephemeral_harness"

sdk_ephemeral_stderr="$work_root/sdk-ephemeral.stderr"
if ! "$work_root/sdk_ephemeral_harness" "$root_domain" 2>"$sdk_ephemeral_stderr"; then
    fail "SDK ephemeral harness failed"
fi
if ! grep -q "use set --ephemeral to update it: SDK_EPHEMERAL" "$sdk_ephemeral_stderr"; then
    fail "SDK ephemeral write rejection was not explicit"
fi

cat >"$work_root/sdk_ephemeral_enumeration_harness.c" <<'C'
#include "secdat-sdk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static const struct secdat_sdk_key_metadata *find_key(
    const struct secdat_sdk_key_metadata_list *keys,
    const char *key
)
{
    size_t index;

    for (index = 0; index < keys->count; index += 1) {
        if (strcmp(keys->items[index].key, key) == 0) {
            return &keys->items[index];
        }
    }
    return NULL;
}

int main(int argc, char **argv)
{
    struct secdat_sdk_options options = {0};
    struct secdat_sdk_list_filters filters = {0};
    struct secdat_sdk_key_metadata_list keys = {0};
    const struct secdat_sdk_key_metadata *item;

    if (argc != 3) {
        fail("expected root and child domain paths");
    }

    options.dir = argv[2];
    options.store = "team";
    filters.include_pattern = "SDK_MASKED_EPHEMERAL";
    filters.bulk_gate = 1;
    if (secdat_sdk_list_keys(&options, &filters, &keys) != 0) {
        fail("SDK list rejected tombstone-shadowing ephemeral key");
    }
    item = find_key(&keys, "SDK_MASKED_EPHEMERAL");
    if (keys.count != 1 || item == NULL
        || strcmp(item->storage_mode, "ephemeral") != 0
        || strcmp(item->bulk_select, "include") != 0) {
        fail("SDK list omitted or misclassified tombstone-shadowing ephemeral key");
    }
    secdat_sdk_free(keys.items);
    memset(&keys, 0, sizeof(keys));
    memset(&filters, 0, sizeof(filters));

    options.dir = argv[1];
    options.store = "enumeration";
    filters.include_pattern = "SDK_HIDDEN_EPHEMERAL";
    if (secdat_sdk_list_keys(&options, &filters, &keys) != 0) {
        fail("SDK list authenticated a shadowed v2 hidden backing key");
    }
    item = find_key(&keys, "SDK_HIDDEN_EPHEMERAL");
    if (keys.count != 1 || item == NULL
        || strcmp(item->storage_mode, "ephemeral") != 0
        || strcmp(item->key_visibility, "unlocked") != 0) {
        fail("SDK list omitted or misclassified v2-hidden ephemeral key");
    }
    secdat_sdk_free(keys.items);
    return 0;
}
C

cc -I"$source_root/src" -I"$build_root/src" "$work_root/sdk_ephemeral_enumeration_harness.c" \
    -L"$build_root/src/.libs" "${sdk_static_link_flags[@]}" \
    -Wl,-rpath,"$build_root/src/.libs" \
    -o "$work_root/sdk_ephemeral_enumeration_harness"

sdk_ephemeral_enumeration_stderr="$work_root/sdk-ephemeral-enumeration.stderr"
if ! SECDAT_MASTER_KEY=unrelated-sdk-process-key \
    "$work_root/sdk_ephemeral_enumeration_harness" "$root_domain" "$child_domain" \
    2>"$sdk_ephemeral_enumeration_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$sdk_ephemeral_enumeration_stderr")" >&2
    fail "SDK ephemeral enumeration harness failed"
fi
if test -s "$sdk_ephemeral_enumeration_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$sdk_ephemeral_enumeration_stderr")" >&2
    fail "SDK ephemeral enumeration wrote unexpected stderr"
fi

cat >"$work_root/sdk_ephemeral_race_harness.c" <<'C'
#include "secdat-sdk.h"

#include <string.h>

int main(int argc, char **argv)
{
    struct secdat_sdk_options options = {0};
    const unsigned char update[] = "must-not-persist";

    if (argc != 2) {
        return 2;
    }
    options.dir = argv[1];
    options.store = "team";
    return secdat_sdk_write_at_preserve_attrs(
        &options,
        "SDK_EPHEMERAL_RACE",
        update,
        strlen((const char *)update),
        0,
        0
    ) == 0;
}
C

cc -I"$source_root/src" -I"$build_root/src" "$work_root/sdk_ephemeral_race_harness.c" \
    -L"$build_root/src/.libs" "${sdk_static_link_flags[@]}" \
    -Wl,-rpath,"$build_root/src/.libs" \
    -o "$work_root/sdk_ephemeral_race_harness"

python3 - "$work_root/sdk_ephemeral_race_harness" "$bin_path" "$root_domain" <<'PY'
import os
import socket
import subprocess
import sys

harness, bin_path, domain = sys.argv[1:]
update_controller, update_worker = socket.socketpair()
lock_controller, lock_worker = socket.socketpair()
writer_env = os.environ.copy()
writer_env["SECDAT_TEST_SDK_UPDATE_SYNC_FD"] = str(update_worker.fileno())
writer = subprocess.Popen(
    [harness, domain],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=writer_env,
    pass_fds=(update_worker.fileno(),),
)
update_worker.close()
update_controller.settimeout(10)
if update_controller.recv(1) != b"R":
    writer.kill()
    raise SystemExit("SDK atomic writer did not pause after reading the ephemeral value")

remover_env = os.environ.copy()
remover_env["SECDAT_TEST_TRANSACTION_LOCK_ATTEMPT_FD"] = str(lock_worker.fileno())
remover = subprocess.Popen(
    [bin_path, "--dir", domain, "--store", "team", "rm", "--ephemeral", "SDK_EPHEMERAL_RACE"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=remover_env,
    pass_fds=(lock_worker.fileno(),),
)
lock_worker.close()
lock_controller.settimeout(10)
if lock_controller.recv(1) != b"B":
    writer.kill()
    remover.kill()
    raise SystemExit("ephemeral remover did not wait for the SDK update lock")
if remover.poll() is not None:
    writer.kill()
    raise SystemExit("ephemeral remover bypassed the SDK update lock")

update_controller.sendall(b"G")
update_controller.close()
writer_stdout, writer_stderr = writer.communicate(timeout=10)
remover_stdout, remover_stderr = remover.communicate(timeout=10)
if (
    writer.returncode != 0
    or writer_stdout != b""
    or b"use set --ephemeral to update it: SDK_EPHEMERAL_RACE" not in writer_stderr
):
    raise SystemExit(
        f"SDK atomic writer did not reject the paused ephemeral value: "
        f"rc={writer.returncode} stdout={writer_stdout!r} stderr={writer_stderr!r}"
    )
if remover.returncode != 0 or remover_stdout != b"" or remover_stderr != b"":
    raise SystemExit(
        f"ephemeral remover failed after SDK update rejection: "
        f"rc={remover.returncode} stdout={remover_stdout!r} stderr={remover_stderr!r}"
    )
PY

sdk_ephemeral_race_value="$($bin_path --dir "$root_domain" --store team get SDK_EPHEMERAL_RACE --stdout)"
if test "$sdk_ephemeral_race_value" != "persisted-race-value"; then
    fail "SDK atomic write persisted stale ephemeral plaintext after concurrent removal"
fi

expiry_race_unlock_stdout="$work_root/expiry-race-unlock.stdout"
expiry_race_unlock_stderr="$work_root/expiry-race-unlock.stderr"
expiry_race_idle_seconds=5
if ! SECDAT_SESSION_IDLE_SECONDS="$expiry_race_idle_seconds" "$bin_path" --dir "$ephemeral_expiry_race_domain" unlock --volatile >"$expiry_race_unlock_stdout" 2>"$expiry_race_unlock_stderr"; then
    fail "failed to start SDK expiry-race ephemeral session"
fi
if ! grep -q "resolved domain: $ephemeral_expiry_race_domain" "$expiry_race_unlock_stderr"; then
    fail "SDK expiry-race unlock did not report its domain"
fi
run_secdat --dir "$ephemeral_expiry_race_domain" --store team set --ephemeral SDK_EPHEMERAL_RACE --value ephemeral-expiry-race-value

python3 - "$work_root/sdk_ephemeral_race_harness" "$ephemeral_expiry_race_domain" "$expiry_race_idle_seconds" <<'PY'
import os
import socket
import subprocess
import sys
import time

harness, domain, idle_seconds_text = sys.argv[1:]
controller, worker = socket.socketpair()
writer_env = os.environ.copy()
writer_env["SECDAT_TEST_SDK_UPDATE_SYNC_FD"] = str(worker.fileno())
writer = subprocess.Popen(
    [harness, domain],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=writer_env,
    pass_fds=(worker.fileno(),),
)
worker.close()
controller.settimeout(10)
if controller.recv(1) != b"R":
    writer.kill()
    raise SystemExit("SDK atomic writer did not pause before session expiry")

time.sleep(int(idle_seconds_text) + 1)
controller.sendall(b"G")
controller.close()
writer_stdout, writer_stderr = writer.communicate(timeout=10)
if (
    writer.returncode != 0
    or writer_stdout != b""
    or b"use set --ephemeral to update it: SDK_EPHEMERAL_RACE" not in writer_stderr
):
    raise SystemExit(
        f"SDK atomic writer lost its initial ephemeral precondition after expiry: "
        f"rc={writer.returncode} stdout={writer_stdout!r} stderr={writer_stderr!r}"
    )
PY

sdk_ephemeral_expiry_race_value="$($bin_path --dir "$ephemeral_expiry_race_domain" --store team get SDK_EPHEMERAL_RACE --stdout)"
if test "$sdk_ephemeral_expiry_race_value" != "persisted-expiry-race-value"; then
    fail "SDK atomic write persisted stale ephemeral plaintext after session expiry"
fi

cat >"$work_root/sdk_lock_harness.c" <<'C'
#include "secdat-sdk.h"

#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

struct worker_args {
    const struct secdat_sdk_options *options;
    const char *key;
};

static void *run_worker(void *raw_args)
{
    const struct worker_args *args = raw_args;
    const unsigned char value[] = "sdk-lock-serialized-value";
    int status = secdat_sdk_set(
        args->options,
        args->key,
        value,
        strlen((const char *)value),
        0
    );

    if (status == 0) {
        (void)write(STDOUT_FILENO, "D", 1);
    }
    return (void *)(intptr_t)status;
}

int main(int argc, char **argv)
{
    struct secdat_sdk_options options = {0};
    struct worker_args args[2];
    pthread_t workers[2];
    void *result = NULL;
    size_t index;

    if (argc != 2) {
        return 2;
    }
    options.dir = argv[1];
    options.store = "team";
    args[0].options = &options;
    args[0].key = "SDK_LOCK_SERIALIZED_A";
    args[1].options = &options;
    args[1].key = "SDK_LOCK_SERIALIZED_B";
    for (index = 0; index < 2; index += 1) {
        if (pthread_create(&workers[index], NULL, run_worker, &args[index]) != 0) {
            return 1;
        }
    }
    for (index = 0; index < 2; index += 1) {
        if (pthread_join(workers[index], &result) != 0
            || (intptr_t)result != 0) {
            return 1;
        }
    }
    return 0;
}
C

cc -I"$source_root/src" -I"$build_root/src" "$work_root/sdk_lock_harness.c" \
    -L"$build_root/src/.libs" "${sdk_static_link_flags[@]}" \
    -pthread \
    -Wl,-rpath,"$build_root/src/.libs" \
    -o "$work_root/sdk_lock_harness"

python3 - "$work_root/sdk_lock_harness" "$root_domain" "$XDG_DATA_HOME/secdat/transactions/lock" <<'PY'
import fcntl
import os
import select
import socket
import subprocess
import sys

harness, domain, lock_path = sys.argv[1:]
lock_file = open(lock_path, "a+b")
fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
controller, worker = socket.socketpair()
child_env = os.environ.copy()
child_env["SECDAT_TEST_TRANSACTION_LOCK_ATTEMPT_FD"] = str(worker.fileno())
child = subprocess.Popen(
    [harness, domain],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    env=child_env,
    pass_fds=(worker.fileno(),),
)
worker.close()
controller.settimeout(10)
if controller.recv(1) != b"B":
    child.kill()
    raise SystemExit("SDK writer did not observe the held transaction lock")
ready, _, _ = select.select([child.stdout], [], [], 0.5)
if ready or child.poll() is not None:
    child.kill()
    raise SystemExit("concurrent SDK thread bypassed the transaction lock")
fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
stdout, stderr = child.communicate(timeout=10)
if child.returncode != 0 or stdout != b"DD" or stderr != b"":
    raise SystemExit(
        f"SDK writer failed after lock release: rc={child.returncode} "
        f"stdout={stdout!r} stderr={stderr!r}"
    )
PY

for sdk_lock_key in SDK_LOCK_SERIALIZED_A SDK_LOCK_SERIALIZED_B; do
    sdk_lock_value="$($bin_path --dir "$root_domain" --store team get "$sdk_lock_key" --stdout)"
    if test "$sdk_lock_value" != "sdk-lock-serialized-value"; then
        fail "SDK transaction-lock probe did not persist $sdk_lock_key"
    fi
done
run_secdat --dir "$root_domain" --store team rm --ephemeral SDK_EPHEMERAL
run_secdat --dir "$root_domain" --store team rm --ephemeral SDK_EPHEMERAL_DEST
run_secdat --dir "$child_domain" --store team rm --ephemeral SDK_MASKED_EPHEMERAL
run_secdat --dir "$child_domain" --store team unmask SDK_MASKED_EPHEMERAL
run_secdat --dir "$root_domain" --store enumeration rm --ephemeral SDK_HIDDEN_EPHEMERAL
run_secdat --dir "$root_domain" lock

cat >"$work_root/sdk_harness.c" <<'C'
#include "secdat-sdk.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

static int string_has_secret(const char *value)
{
    return strstr(value, "sdk-secret-value") != NULL
        || strstr(value, "public-secret-value") != NULL
        || strstr(value, "bulk-secret-value") != NULL
        || strstr(value, "bulk-updated-value") != NULL
        || strstr(value, "long-primary-value") != NULL
        || strstr(value, "long-secondary-value") != NULL
        || strstr(value, "consumer-token") != NULL;
}

static void assert_no_key_value(const struct secdat_sdk_key_metadata *item)
{
    if (string_has_secret(item->key)
        || string_has_secret(item->store)
        || string_has_secret(item->canonical_keyref)
        || string_has_secret(item->source_domain)
        || string_has_secret(item->source_type)
        || string_has_secret(item->storage_mode)
        || string_has_secret(item->key_visibility)
        || string_has_secret(item->value_access)
        || string_has_secret(item->bulk_select)) {
        fail("key metadata exposed a secret value");
    }
}

static const struct secdat_sdk_key_metadata *find_key(
    const struct secdat_sdk_key_metadata_list *list,
    const char *key
)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].key, key) == 0) {
            return &list->items[index];
        }
    }
    return NULL;
}

static int contains_store(const struct secdat_sdk_store_metadata_list *list, const char *name)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].name, name) == 0) {
            return 1;
        }
    }
    return 0;
}

static int contains_domain(const struct secdat_sdk_domain_metadata_list *list, const char *root)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].root, root) == 0) {
            return 1;
        }
    }
    return 0;
}

static const struct secdat_sdk_domain_metadata *find_domain(
    const struct secdat_sdk_domain_metadata_list *list,
    const char *root
)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        if (strcmp(list->items[index].root, root) == 0) {
            return &list->items[index];
        }
    }
    return NULL;
}

static const struct secdat_sdk_relation_refresh_suggestion *find_refresh_suggestion(
    const struct secdat_sdk_relation_refresh_suggestion_list *list,
    const char *relation_id,
    const char *leaked_role,
    const char *refresh_role,
    const char *refresh_keyref,
    const char *reason
)
{
    size_t index;

    for (index = 0; index < list->count; index += 1) {
        const struct secdat_sdk_relation_refresh_suggestion *item = &list->items[index];

        if (strcmp(item->severity, "high") == 0
            && strcmp(item->relation_id, relation_id) == 0
            && strcmp(item->leaked_role, leaked_role) == 0
            && strcmp(item->refresh_role, refresh_role) == 0
            && strcmp(item->refresh_keyref, refresh_keyref) == 0
            && strcmp(item->reason, reason) == 0) {
            return item;
        }
    }
    return NULL;
}

static void assert_no_refresh_secret(const struct secdat_sdk_relation_refresh_suggestion *item)
{
    if (string_has_secret(item->severity)
        || string_has_secret(item->relation_id)
        || string_has_secret(item->leaked_role)
        || string_has_secret(item->refresh_role)
        || string_has_secret(item->refresh_keyref)
        || string_has_secret(item->reason)) {
        fail("relation refresh suggestion exposed a secret value");
    }
}

static void format_expected_keyref(char *buffer, size_t size, const char *domain, const char *keyref)
{
    int written = snprintf(buffer, size, "%s/%s", domain, keyref);

    if (written < 0 || (size_t)written >= size) {
        fail("expected keyref path was too long");
    }
}

int main(int argc, char **argv)
{
    const char *root;
    const char *child;
    const char *orphaned_child;
    const char *refresh_domain;
    const char *long_role;
    struct secdat_sdk_options root_options = {0};
    struct secdat_sdk_options child_options = {0};
    struct secdat_sdk_list_filters public_filter = {0};
    struct secdat_sdk_list_filters bulk_filter = {0};
    struct secdat_sdk_domain_filters domain_filters = {0};
    struct secdat_sdk_key_metadata_list keys = {0};
    struct secdat_sdk_key_metadata_list public_keys = {0};
    struct secdat_sdk_key_metadata_list bulk_keys = {0};
    struct secdat_sdk_key_metadata_list child_keys = {0};
    struct secdat_sdk_store_metadata_list stores = {0};
    struct secdat_sdk_domain_metadata_list domains = {0};
    struct secdat_sdk_relation_refresh_suggestion_list refreshes = {0};
    struct secdat_sdk_relation_refresh_suggestion_list public_refreshes = {0};
    struct secdat_sdk_relation_refresh_suggestion_list long_refreshes = {0};
    const struct secdat_sdk_key_metadata *api_token;
    const struct secdat_sdk_key_metadata *public_url;
    const struct secdat_sdk_key_metadata *bulk_token;
    const struct secdat_sdk_domain_metadata *orphaned_domain;
    char expected_api_keyref[PATH_MAX * 2];
    char expected_bulk_keyref[PATH_MAX * 2];
    char expected_consumer_keyref[PATH_MAX * 2];
    char expected_long_primary_keyref[PATH_MAX * 2];
    char expected_long_secondary_keyref[PATH_MAX * 2];
    unsigned char *value = NULL;
    size_t value_length = 0;
    int unsafe_store = 0;
    size_t index;

    if (argc != 6) {
        fail("expected root, child, orphaned child, refresh domain, and long role");
    }
    root = argv[1];
    child = argv[2];
    orphaned_child = argv[3];
    refresh_domain = argv[4];
    long_role = argv[5];
    root_options.dir = root;
    root_options.store = "team";
    child_options.dir = child;
    child_options.store = "team";

    if (secdat_sdk_list_stores(&root_options, &stores) != 0) {
        fail("secdat_sdk_list_stores failed");
    }
    if (!contains_store(&stores, "team")) {
        fail("store metadata did not include team");
    }
    secdat_sdk_free(stores.items);

    if (secdat_sdk_list_keys(&root_options, NULL, &keys) != 0) {
        fail("secdat_sdk_list_keys failed");
    }
    for (index = 0; index < keys.count; index += 1) {
        assert_no_key_value(&keys.items[index]);
    }
    api_token = find_key(&keys, "API_TOKEN");
    public_url = find_key(&keys, "PUBLIC_URL");
    bulk_token = find_key(&keys, "BULK_TOKEN");
    if (api_token == NULL || public_url == NULL || bulk_token == NULL) {
        fail("key metadata did not include expected keys");
    }
    if (strcmp(api_token->storage_mode, "safe") != 0 || api_token->unsafe_store) {
        fail("safe key metadata had wrong storage mode");
    }
    if (strcmp(public_url->storage_mode, "unsafe") != 0 || !public_url->unsafe_store) {
        fail("unsafe key metadata had wrong storage mode");
    }
    if (!api_token->local || api_token->inherited || strcmp(api_token->source_type, "local") != 0) {
        fail("local source metadata was wrong");
    }
    if (strcmp(bulk_token->bulk_select, "include") != 0) {
        fail("bulk key metadata had wrong inject bulk policy");
    }
    secdat_sdk_free(keys.items);

    if (secdat_sdk_set_preserve_attrs(
            &root_options,
            "BULK_TOKEN",
            (const unsigned char *)"bulk-updated-value",
            strlen("bulk-updated-value")) != 0) {
        fail("secdat_sdk_set_preserve_attrs failed");
    }
    if (secdat_sdk_get(&root_options, "BULK_TOKEN", &value, &value_length, &unsafe_store) != 0) {
        fail("secdat_sdk_get after preserve attrs failed");
    }
    if (unsafe_store || value_length != strlen("bulk-updated-value")
        || memcmp(value, "bulk-updated-value", value_length) != 0) {
        fail("secdat_sdk_set_preserve_attrs wrote the wrong value or storage mode");
    }
    secdat_sdk_free(value);
    value = NULL;
    value_length = 0;

    if (secdat_sdk_write_at_preserve_attrs(
            &root_options,
            "BULK_TOKEN",
            (const unsigned char *)"-tail",
            strlen("-tail"),
            0,
            1
        ) != 0) {
        fail("secdat_sdk_write_at_preserve_attrs failed");
    }
    if (secdat_sdk_get(&root_options, "BULK_TOKEN", &value, &value_length, &unsafe_store) != 0
        || unsafe_store
        || value_length != strlen("bulk-updated-value-tail")
        || memcmp(value, "bulk-updated-value-tail", value_length) != 0) {
        fail("secdat_sdk_write_at_preserve_attrs wrote the wrong value");
    }
    secdat_sdk_free(value);
    value = NULL;
    value_length = 0;
    if (secdat_sdk_resize_preserve_attrs(
            &root_options,
            "BULK_TOKEN",
            strlen("bulk-updated-value")
        ) != 0) {
        fail("secdat_sdk_resize_preserve_attrs failed");
    }
    if (secdat_sdk_get(&root_options, "BULK_TOKEN", &value, &value_length, &unsafe_store) != 0
        || unsafe_store
        || value_length != strlen("bulk-updated-value")
        || memcmp(value, "bulk-updated-value", value_length) != 0) {
        fail("secdat_sdk_resize_preserve_attrs wrote the wrong value");
    }
    secdat_sdk_free(value);
    value = NULL;
    value_length = 0;

    bulk_filter.include_pattern = "BULK_*";
    bulk_filter.bulk_gate = 1;
    if (secdat_sdk_list_keys(&root_options, &bulk_filter, &bulk_keys) != 0) {
        fail("bulk filtered secdat_sdk_list_keys failed");
    }
    if (bulk_keys.count != 1
        || strcmp(bulk_keys.items[0].key, "BULK_TOKEN") != 0
        || strcmp(bulk_keys.items[0].bulk_select, "include") != 0) {
        fail("secdat_sdk_set_preserve_attrs did not preserve inject bulk metadata");
    }
    secdat_sdk_free(bulk_keys.items);

    public_filter.include_pattern = "PUBLIC_*";
    public_filter.unsafe_store = 1;
    if (secdat_sdk_list_keys(&root_options, &public_filter, &public_keys) != 0) {
        fail("filtered secdat_sdk_list_keys failed");
    }
    if (public_keys.count != 1 || strcmp(public_keys.items[0].key, "PUBLIC_URL") != 0) {
        fail("key metadata filters returned wrong keys");
    }
    assert_no_key_value(&public_keys.items[0]);
    secdat_sdk_free(public_keys.items);

    if (secdat_sdk_list_keys(&child_options, NULL, &child_keys) != 0) {
        fail("child secdat_sdk_list_keys failed");
    }
    api_token = find_key(&child_keys, "API_TOKEN");
    if (api_token == NULL || !api_token->inherited || api_token->local || strcmp(api_token->source_type, "inherited") != 0) {
        fail("inherited source metadata was wrong");
    }
    secdat_sdk_free(child_keys.items);

    format_expected_keyref(expected_api_keyref, sizeof(expected_api_keyref), root, "API_TOKEN:team");
    format_expected_keyref(expected_bulk_keyref, sizeof(expected_bulk_keyref), root, "BULK_TOKEN:team");
    format_expected_keyref(expected_consumer_keyref, sizeof(expected_consumer_keyref), refresh_domain, "CONSUMER_TOKEN:default");
    format_expected_keyref(expected_long_primary_keyref, sizeof(expected_long_primary_keyref), root, "LONG_PRIMARY:team");
    format_expected_keyref(expected_long_secondary_keyref, sizeof(expected_long_secondary_keyref), root, "LONG_SECONDARY:team");
    if (secdat_sdk_relation_suggest_refresh(&root_options, "API_TOKEN", &refreshes) != 0) {
        fail("secdat_sdk_relation_suggest_refresh failed");
    }
    if (refreshes.count != 4) {
        fail("relation refresh suggestion count mismatch");
    }
    for (index = 0; index < refreshes.count; index += 1) {
        assert_no_refresh_secret(&refreshes.items[index]);
    }
    if (find_refresh_suggestion(
            &refreshes,
            "sdk-refresh",
            "token",
            "token",
            expected_api_keyref,
            "leaked-secret-member") == NULL) {
        fail("missing SDK self refresh suggestion");
    }
    if (find_refresh_suggestion(
            &refreshes,
            "sdk-refresh",
            "token",
            "bulk_token",
            expected_bulk_keyref,
            "combination-sensitive-relation") == NULL) {
        fail("missing SDK local related refresh suggestion");
    }
    if (find_refresh_suggestion(
            &refreshes,
            "sdk-cross-refresh",
            "token",
            "token",
            expected_api_keyref,
            "leaked-secret-member") == NULL) {
        fail("missing SDK cross-domain leaked member suggestion");
    }
    if (find_refresh_suggestion(
            &refreshes,
            "sdk-cross-refresh",
            "token",
            "refresh_token",
            expected_consumer_keyref,
            "combination-sensitive-relation") == NULL) {
        fail("missing SDK cross-domain refresh target suggestion");
    }
    secdat_sdk_free(refreshes.items);
    if (secdat_sdk_relation_suggest_refresh(&root_options, "PUBLIC_URL", &public_refreshes) != 0) {
        fail("secdat_sdk_relation_suggest_refresh public role failed");
    }
    if (public_refreshes.count != 0) {
        fail("public relation role should not produce high-risk refresh suggestions");
    }
    secdat_sdk_free(public_refreshes.items);
    if (secdat_sdk_relation_suggest_refresh(&root_options, "LONG_PRIMARY", &long_refreshes) != 0) {
        fail("secdat_sdk_relation_suggest_refresh long role failed");
    }
    if (long_refreshes.count != 2) {
        fail("long role relation refresh suggestion count mismatch");
    }
    for (index = 0; index < long_refreshes.count; index += 1) {
        assert_no_refresh_secret(&long_refreshes.items[index]);
    }
    if (find_refresh_suggestion(
            &long_refreshes,
            "sdk-long-refresh",
            long_role,
            long_role,
            expected_long_primary_keyref,
            "leaked-relation-member") == NULL) {
        fail("missing SDK long role self suggestion");
    }
    if (find_refresh_suggestion(
            &long_refreshes,
            "sdk-long-refresh",
            long_role,
            "secondary",
            expected_long_secondary_keyref,
            "combination-sensitive-relation") == NULL) {
        fail("missing SDK long role related suggestion");
    }
    secdat_sdk_free(long_refreshes.items);

    if (secdat_sdk_wait_unlock(&root_options, 1) != 0) {
        fail("secdat_sdk_wait_unlock did not accept SECDAT_MASTER_KEY");
    }

    domain_filters.include_descendants = 1;
    if (secdat_sdk_list_domains(&root_options, &domain_filters, &domains) != 0) {
        fail("secdat_sdk_list_domains failed");
    }
    if (!contains_domain(&domains, root) || !contains_domain(&domains, child)) {
        fail("domain metadata did not include root and child");
    }
    orphaned_domain = find_domain(&domains, orphaned_child);
    if (orphaned_domain == NULL) {
        fail("domain metadata did not include orphaned child");
    }
    if (!orphaned_domain->orphaned_domain
        || orphaned_domain->unlocked
        || orphaned_domain->key_source != SECDAT_SDK_KEY_SOURCE_ORPHANED
        || orphaned_domain->effective_source != SECDAT_SDK_EFFECTIVE_SOURCE_ORPHANED
        || orphaned_domain->session_expires_at != 0
        || orphaned_domain->remaining_seconds != 0
        || orphaned_domain->related_domain_root[0] != '\0') {
        fail("orphaned domain metadata exposed unlock state");
    }
    secdat_sdk_free(domains.items);

    unsetenv("SECDAT_MASTER_KEY");
    if (secdat_sdk_wait_unlock(&root_options, 1) == 0) {
        fail("secdat_sdk_wait_unlock succeeded while locked");
    }

    return 0;
}
C

cc -I"$source_root/src" -I"$build_root/src" "$work_root/sdk_harness.c" \
    -L"$build_root/src/.libs" "${sdk_static_link_flags[@]}" \
    -Wl,-rpath,"$build_root/src/.libs" \
    -o "$work_root/sdk_harness"

"$work_root/sdk_harness" "$root_domain" "$child_domain" "$orphaned_child_domain" "$refresh_domain" "$long_role"

cli_plan="$work_root/cli-plan.json"
cli_plan_stderr="$work_root/cli-plan.stderr"
sdk_plan="$work_root/sdk-plan.json"
sdk_plan_stderr="$work_root/sdk-plan.stderr"

if ! "$bin_path" --dir "$root_domain" --store team exec \
        --inject "ambient:only=__SDK_NO_AMBIENT__" \
        --inject "secret:only=API_TOKEN:BULK_TOKEN" \
        --inject "route:prefer=secret" \
        --command-resolution direct \
        --dry-run --json \
        python3 -c pass >"$cli_plan" 2>"$cli_plan_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$cli_plan_stderr")" >&2
    fail "CLI exec dry-run JSON plan failed"
fi
if test -s "$cli_plan_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$cli_plan_stderr")" >&2
    fail "unexpected stderr from CLI exec dry-run JSON plan"
fi

cat >"$work_root/sdk_plan_harness.c" <<'C'
#include "secdat-sdk.h"

#include <stdio.h>
#include <stdlib.h>

static void fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    exit(1);
}

int main(int argc, char **argv)
{
    struct secdat_sdk_options options = {0};
    struct secdat_sdk_exec_plan_options plan_options = {0};
    const char *inject_rules[] = {
        "ambient:only=__SDK_NO_AMBIENT__",
        "secret:only=API_TOKEN:BULK_TOKEN",
        "route:prefer=secret",
    };
    const char *command_argv[] = {"python3", "-c", "pass"};
    char *json = NULL;

    if (argc != 2) {
        fail("expected root domain path");
    }
    options.dir = argv[1];
    options.store = "team";
    plan_options.inject_rules = inject_rules;
    plan_options.inject_rule_count = sizeof(inject_rules) / sizeof(inject_rules[0]);
    plan_options.command_resolution = "direct";
    plan_options.argv = command_argv;
    plan_options.argv_count = sizeof(command_argv) / sizeof(command_argv[0]);

    if (secdat_sdk_exec_plan_json(&options, &plan_options, &json) != 0 || json == NULL) {
        fail("secdat_sdk_exec_plan_json failed");
    }
    fputs(json, stdout);
    fputc('\n', stdout);
    secdat_sdk_free(json);
    return 0;
}
C

cc -I"$source_root/src" -I"$build_root/src" "$work_root/sdk_plan_harness.c" \
    -L"$build_root/src/.libs" "${sdk_static_link_flags[@]}" \
    -Wl,-rpath,"$build_root/src/.libs" \
    -o "$work_root/sdk_plan_harness"

if ! "$work_root/sdk_plan_harness" "$root_domain" >"$sdk_plan" 2>"$sdk_plan_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$sdk_plan_stderr")" >&2
    fail "SDK exec JSON plan harness failed"
fi
if test -s "$sdk_plan_stderr"; then
    printf 'stderr:\n%s\n' "$(cat "$sdk_plan_stderr")" >&2
    fail "unexpected stderr from SDK exec JSON plan harness"
fi

python3 - "$cli_plan" "$sdk_plan" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    cli_plan = json.load(handle)
with open(sys.argv[2], encoding="utf-8") as handle:
    sdk_plan = json.load(handle)

if sdk_plan != cli_plan:
    raise SystemExit(f"FAIL: SDK exec plan JSON differed from CLI dry-run\nCLI={cli_plan!r}\nSDK={sdk_plan!r}")
if sdk_plan.get("ok") is not True:
    raise SystemExit(f"FAIL: SDK exec plan should be ok: {sdk_plan!r}")
if sdk_plan.get("command_resolution") != "direct":
    raise SystemExit(f"FAIL: SDK exec plan command resolution mismatch: {sdk_plan!r}")
if sdk_plan.get("argv") != ["python3", "-c", "pass"]:
    raise SystemExit(f"FAIL: SDK exec plan argv mismatch: {sdk_plan!r}")
if sdk_plan.get("supply", {}).get("ambient", {}).get("contributed") != []:
    raise SystemExit(f"FAIL: SDK exec plan ambient selection should be empty: {sdk_plan!r}")
if {item["key"] for item in sdk_plan.get("injected_keys", [])} != {"API_TOKEN", "BULK_TOKEN"}:
    raise SystemExit(f"FAIL: SDK exec plan injected keys mismatch: {sdk_plan!r}")

serialized = json.dumps(sdk_plan, sort_keys=True)
for secret in ["sdk-secret-value", "public-secret-value", "bulk-secret-value", "bulk-updated-value"]:
    if secret in serialized:
        raise SystemExit(f"FAIL: SDK exec plan exposed a secret value: {secret!r}")
PY

if test -n "$shared_library_path"; then
PYTHONPATH="$source_root/bindings/python" SECDAT_SDK_LIBRARY="$shared_library_path" \
python3 - "$root_domain" "$refresh_domain" "$long_role" "$cli_plan" <<'PY'
import json
import os
import sys
import tempfile

from secdat_sdk import RedactionFieldClass, Secdat, SecdatError

root = sys.argv[1]
refresh_domain = sys.argv[2]
long_role = sys.argv[3]
cli_plan_path = sys.argv[4]
secret_values = [
    "sdk-secret-value",
    "public-secret-value",
    "bulk-secret-value",
    "bulk-updated-value",
    "long-primary-value",
    "long-secondary-value",
    "consumer-token",
]


def fail(message):
    raise SystemExit(f"FAIL: {message}")


def assert_no_secret_text(value, label):
    for secret in secret_values:
        if secret in value:
            fail(f"{label} exposed a secret value: {secret!r}")


def find_refresh_suggestion(suggestions, relation_id, leaked_role, refresh_role, refresh_keyref, reason):
    for item in suggestions:
        if (
            item.severity == "high"
            and item.relation_id == relation_id
            and item.leaked_role == leaked_role
            and item.refresh_role == refresh_role
            and item.refresh_keyref == refresh_keyref
            and item.reason == reason
        ):
            return item
    return None


def call_with_c_stderr_suppressed(callback):
    saved_stderr = os.dup(2)
    try:
        with tempfile.TemporaryFile() as captured:
            os.dup2(captured.fileno(), 2)
            try:
                return callback()
            finally:
                os.dup2(saved_stderr, 2)
    finally:
        os.close(saved_stderr)


sdk = Secdat()
plan_json = sdk.exec_plan_json(
    ["python3", "-c", "pass"],
    dir=root,
    store="team",
    inject_rules=[
        "ambient:only=__SDK_NO_AMBIENT__",
        "secret:only=API_TOKEN:BULK_TOKEN",
        "route:prefer=secret",
    ],
    command_resolution="direct",
)
with open(cli_plan_path, encoding="utf-8") as handle:
    cli_plan = json.load(handle)
python_plan = json.loads(plan_json)
if python_plan != cli_plan:
    fail(f"Python SDK exec plan JSON differed from CLI dry-run\nCLI={cli_plan!r}\nPython={python_plan!r}")
assert_no_secret_text(json.dumps(python_plan, sort_keys=True), "Python SDK exec plan")

if sdk.redaction_class_name(RedactionFieldClass.SECRET_VALUE) != "secret_value":
    fail("Python SDK redaction class name mismatch")
if sdk.redaction_policy_name(RedactionFieldClass.SECRET_VALUE) != "redact":
    fail("Python SDK redaction policy mismatch")
if sdk.redaction_display_label(RedactionFieldClass.SECRET_VALUE) != "secret value":
    fail("Python SDK redaction display label mismatch")
if sdk.redaction_value_allowed(RedactionFieldClass.SECRET_VALUE):
    fail("Python SDK redaction should not allow secret values")
classification = sdk.describe_redaction_class(RedactionFieldClass.SECRET_DERIVED_IDENTIFIER)
if (
    classification.field_class != RedactionFieldClass.SECRET_DERIVED_IDENTIFIER
    or classification.class_name != "secret_derived_identifier"
    or classification.policy_name != "label-only"
    or not classification.value_allowed
):
    fail(f"Python SDK redaction classification mismatch: {classification!r}")
field_classification = sdk.classify_exec_json_field("injected_keys.key")
if field_classification.field_class != RedactionFieldClass.SECRET_DERIVED_IDENTIFIER:
    fail(f"Python SDK exec JSON field classification mismatch: {field_classification!r}")
try:
    sdk.classify_exec_json_field("unknown.field")
except SecdatError:
    pass
else:
    fail("Python SDK unknown exec JSON field should fail closed")
invalid_plan_json = call_with_c_stderr_suppressed(
    lambda: sdk.exec_plan_json(
        ["env"],
        dir=root,
        store="team",
        inject_rules=["secret:require=MISSING_SDK_TOKEN"],
        command_resolution="direct",
    )
)
invalid_plan = json.loads(invalid_plan_json)
missing_required = invalid_plan.get("supply", {}).get("secret", {}).get("missing_required", [])
if invalid_plan.get("ok") is not False or "MISSING_SDK_TOKEN" not in missing_required:
    fail(f"Python SDK invalid exec plan did not return failure JSON: {invalid_plan!r}")
assert_no_secret_text(json.dumps(invalid_plan, sort_keys=True), "Python SDK invalid exec plan")
for text in [
    classification.class_name,
    classification.policy_name,
    classification.display_label,
    field_classification.class_name,
    field_classification.policy_name,
    field_classification.display_label,
]:
    assert_no_secret_text(text, "Python SDK redaction metadata")

api_keyref = f"{root}/API_TOKEN:team"
bulk_keyref = f"{root}/BULK_TOKEN:team"
consumer_keyref = f"{refresh_domain}/CONSUMER_TOKEN:default"
long_primary_keyref = f"{root}/LONG_PRIMARY:team"
long_secondary_keyref = f"{root}/LONG_SECONDARY:team"

refreshes = sdk.relation_suggest_refresh("API_TOKEN", dir=root, store="team")
if len(refreshes) != 4:
    fail(f"Python SDK relation refresh count mismatch: {refreshes!r}")
for item in refreshes:
    assert_no_secret_text(json.dumps(vars(item), sort_keys=True), "Python SDK relation refresh")
if find_refresh_suggestion(refreshes, "sdk-refresh", "token", "token", api_keyref, "leaked-secret-member") is None:
    fail("missing Python SDK self refresh suggestion")
if find_refresh_suggestion(refreshes, "sdk-refresh", "token", "bulk_token", bulk_keyref, "combination-sensitive-relation") is None:
    fail("missing Python SDK local related refresh suggestion")
if find_refresh_suggestion(refreshes, "sdk-cross-refresh", "token", "token", api_keyref, "leaked-secret-member") is None:
    fail("missing Python SDK cross-domain leaked member suggestion")
if find_refresh_suggestion(refreshes, "sdk-cross-refresh", "token", "refresh_token", consumer_keyref, "combination-sensitive-relation") is None:
    fail("missing Python SDK cross-domain refresh target suggestion")

public_refreshes = sdk.relation_suggest_refresh("PUBLIC_URL", dir=root, store="team")
if public_refreshes:
    fail(f"Python SDK public role should not produce refresh suggestions: {public_refreshes!r}")

long_refreshes = sdk.relation_suggest_refresh("LONG_PRIMARY", dir=root, store="team")
if len(long_refreshes) != 2:
    fail(f"Python SDK long role refresh count mismatch: {long_refreshes!r}")
if find_refresh_suggestion(long_refreshes, "sdk-long-refresh", long_role, long_role, long_primary_keyref, "leaked-relation-member") is None:
    fail("missing Python SDK long role self suggestion")
if find_refresh_suggestion(long_refreshes, "sdk-long-refresh", long_role, "secondary", long_secondary_keyref, "combination-sensitive-relation") is None:
    fail("missing Python SDK long role related suggestion")
for item in long_refreshes:
    assert_no_secret_text(json.dumps(vars(item), sort_keys=True), "Python SDK long relation refresh")
PY
else
    printf 'SKIP Python SDK regression: shared libraries disabled\n'
fi

go_pkg_config_dir="$work_root/go-pkgconfig"
go_harness_dir="$work_root/go-sdk-harness"
go_bin="${GO:-}"
go_skip_reason=
go_usable() {
    local candidate="$1"

    test -n "$candidate" || return 1
    command -v "$candidate" >/dev/null 2>&1 || test -x "$candidate" || return 1
    "$candidate" version >/dev/null 2>&1 || return 1
}
if test -z "$go_bin"; then
    if command -v go >/dev/null 2>&1; then
        go_bin="$(command -v go)"
    elif test -x /snap/bin/go; then
        go_bin=/snap/bin/go
    elif test -x /usr/local/go/bin/go; then
        go_bin=/usr/local/go/bin/go
    fi
fi
if test -n "$go_bin" && ! go_usable "$go_bin"; then
    go_skip_reason="go not runnable: $go_bin"
    go_bin=
fi
if test -z "$go_bin"; then
    printf 'SKIP Go SDK binding smoke: %s\n' "${go_skip_reason:-go not found}"
else
mkdir -p "$go_pkg_config_dir" "$go_harness_dir"
cat >"$go_pkg_config_dir/libsecdat.pc" <<EOF
prefix=$source_root
exec_prefix=\${prefix}
libdir=$build_root/src/.libs
includedir=$source_root/src

Name: libsecdat
Description: C SDK for secdat secret access and session control
Version: 0.6.1
Libs: -L\${libdir} -Wl,-rpath,\${libdir} -lsecdat
Libs.private: $sdk_private_link_flags_text
Cflags: -I\${includedir} -I$build_root/src
EOF
cat >"$go_harness_dir/go.mod" <<EOF
module secdat-go-sdk-regression

go 1.21

require github.com/mako10k/secdat/bindings/go v0.0.0

replace github.com/mako10k/secdat/bindings/go => $source_root/bindings/go
EOF
cat >"$go_harness_dir/main.go" <<'GO'
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"syscall"

	"github.com/mako10k/secdat/bindings/go/secdat"
)

var secretValues = []string{
	"sdk-secret-value",
	"public-secret-value",
	"bulk-secret-value",
	"bulk-updated-value",
	"long-primary-value",
	"long-secondary-value",
	"consumer-token",
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", args...)
	os.Exit(1)
}

func assertNoSecretText(value string, label string) {
	for _, secret := range secretValues {
		if strings.Contains(value, secret) {
			fail("%s exposed a secret value: %q", label, secret)
		}
	}
}

func parseJSON(value string) map[string]any {
	var parsed map[string]any
	if err := json.Unmarshal([]byte(value), &parsed); err != nil {
		fail("failed to parse JSON: %v", err)
	}
	return parsed
}

func readJSON(path string) map[string]any {
	payload, err := os.ReadFile(path)
	if err != nil {
		fail("failed to read %s: %v", path, err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(payload, &parsed); err != nil {
		fail("failed to parse %s: %v", path, err)
	}
	return parsed
}

func compactJSON(value any) string {
	payload, err := json.Marshal(value)
	if err != nil {
		fail("failed to encode JSON: %v", err)
	}
	return string(payload)
}

func callWithCStderrSuppressed(callback func() (string, error)) (string, error) {
	savedStderr, err := syscall.Dup(2)
	if err != nil {
		return "", err
	}
	defer syscall.Close(savedStderr)

	captured, err := os.CreateTemp("", "secdat-go-sdk-stderr-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(captured.Name())
	defer captured.Close()

	if err := syscall.Dup2(int(captured.Fd()), 2); err != nil {
		return "", err
	}
	defer syscall.Dup2(savedStderr, 2)

	return callback()
}

func findRefreshSuggestion(
	suggestions []secdat.RelationRefreshSuggestion,
	relationID string,
	leakedRole string,
	refreshRole string,
	refreshKeyref string,
	reason string,
) *secdat.RelationRefreshSuggestion {
	for index := range suggestions {
		item := &suggestions[index]
		if item.Severity == "high" &&
			item.RelationID == relationID &&
			item.LeakedRole == leakedRole &&
			item.RefreshRole == refreshRole &&
			item.RefreshKeyref == refreshKeyref &&
			item.Reason == reason {
			return item
		}
	}
	return nil
}

func main() {
	if len(os.Args) != 5 {
		fail("expected root, refresh domain, long role, and CLI plan path")
	}
	root := os.Args[1]
	refreshDomain := os.Args[2]
	longRole := os.Args[3]
	cliPlanPath := os.Args[4]
	options := secdat.Options{Dir: root, Store: "team"}

	planJSON, err := secdat.ExecPlanJSON(options, secdat.ExecPlanOptions{
		Argv: []string{"python3", "-c", "pass"},
		InjectRules: []string{
			"ambient:only=__SDK_NO_AMBIENT__",
			"secret:only=API_TOKEN:BULK_TOKEN",
			"route:prefer=secret",
		},
		CommandResolution: "direct",
	})
	if err != nil {
		fail("Go SDK exec plan failed: %v", err)
	}
	cliPlan := readJSON(cliPlanPath)
	goPlan := parseJSON(planJSON)
	if !reflect.DeepEqual(goPlan, cliPlan) {
		fail("Go SDK exec plan JSON differed from CLI dry-run\nCLI=%#v\nGo=%#v", cliPlan, goPlan)
	}
	assertNoSecretText(compactJSON(goPlan), "Go SDK exec plan")

	className, err := secdat.RedactionClassName(secdat.RedactionSecretValue)
	if err != nil || className != "secret_value" {
		fail("Go SDK redaction class name mismatch: %q %v", className, err)
	}
	policyName, err := secdat.RedactionPolicyName(secdat.RedactionSecretValue)
	if err != nil || policyName != "redact" {
		fail("Go SDK redaction policy mismatch: %q %v", policyName, err)
	}
	displayLabel, err := secdat.RedactionDisplayLabel(secdat.RedactionSecretValue)
	if err != nil || displayLabel != "secret value" {
		fail("Go SDK redaction display label mismatch: %q %v", displayLabel, err)
	}
	if secdat.RedactionValueAllowed(secdat.RedactionSecretValue) {
		fail("Go SDK redaction should not allow secret values")
	}
	classification, err := secdat.DescribeRedactionClass(secdat.RedactionSecretDerivedIdentifier)
	if err != nil ||
		classification.FieldClass != secdat.RedactionSecretDerivedIdentifier ||
		classification.ClassName != "secret_derived_identifier" ||
		classification.PolicyName != "label-only" ||
		!classification.ValueAllowed {
		fail("Go SDK redaction classification mismatch: %#v %v", classification, err)
	}
	fieldClassification, err := secdat.ClassifyExecJSONField("injected_keys.key")
	if err != nil || fieldClassification.FieldClass != secdat.RedactionSecretDerivedIdentifier {
		fail("Go SDK exec JSON field classification mismatch: %#v %v", fieldClassification, err)
	}
	if _, err := secdat.ClassifyExecJSONField("unknown.field"); err == nil {
		fail("Go SDK unknown exec JSON field should fail closed")
	}
	redactionMetadata := []string{
		classification.ClassName,
		classification.PolicyName,
		classification.DisplayLabel,
		fieldClassification.ClassName,
		fieldClassification.PolicyName,
		fieldClassification.DisplayLabel,
	}
	for _, text := range redactionMetadata {
		assertNoSecretText(text, "Go SDK redaction metadata")
	}

	invalidPlanJSON, err := callWithCStderrSuppressed(func() (string, error) {
		return secdat.ExecPlanJSON(options, secdat.ExecPlanOptions{
			Argv:              []string{"env"},
			InjectRules:       []string{"secret:require=MISSING_GO_TOKEN"},
			CommandResolution: "direct",
		})
	})
	if err != nil {
		fail("Go SDK invalid exec plan should return JSON: %v", err)
	}
	invalidPlan := parseJSON(invalidPlanJSON)
	if invalidPlan["ok"] != false {
		fail("Go SDK invalid exec plan should set ok=false: %#v", invalidPlan)
	}
	supply, _ := invalidPlan["supply"].(map[string]any)
	secret, _ := supply["secret"].(map[string]any)
	missingRequired, _ := secret["missing_required"].([]any)
	foundMissing := false
	for _, value := range missingRequired {
		if value == "MISSING_GO_TOKEN" {
			foundMissing = true
			break
		}
	}
	if !foundMissing {
		fail("Go SDK invalid exec plan did not report missing required token: %#v", invalidPlan)
	}
	assertNoSecretText(compactJSON(invalidPlan), "Go SDK invalid exec plan")

	apiKeyref := root + "/API_TOKEN:team"
	bulkKeyref := root + "/BULK_TOKEN:team"
	consumerKeyref := refreshDomain + "/CONSUMER_TOKEN:default"
	longPrimaryKeyref := root + "/LONG_PRIMARY:team"
	longSecondaryKeyref := root + "/LONG_SECONDARY:team"

	refreshes, err := secdat.RelationSuggestRefresh(options, "API_TOKEN")
	if err != nil {
		fail("Go SDK relation refresh failed: %v", err)
	}
	if len(refreshes) != 4 {
		fail("Go SDK relation refresh count mismatch: %#v", refreshes)
	}
	assertNoSecretText(compactJSON(refreshes), "Go SDK relation refresh")
	if findRefreshSuggestion(refreshes, "sdk-refresh", "token", "token", apiKeyref, "leaked-secret-member") == nil {
		fail("missing Go SDK self refresh suggestion")
	}
	if findRefreshSuggestion(refreshes, "sdk-refresh", "token", "bulk_token", bulkKeyref, "combination-sensitive-relation") == nil {
		fail("missing Go SDK local related refresh suggestion")
	}
	if findRefreshSuggestion(refreshes, "sdk-cross-refresh", "token", "token", apiKeyref, "leaked-secret-member") == nil {
		fail("missing Go SDK cross-domain leaked member suggestion")
	}
	if findRefreshSuggestion(refreshes, "sdk-cross-refresh", "token", "refresh_token", consumerKeyref, "combination-sensitive-relation") == nil {
		fail("missing Go SDK cross-domain refresh target suggestion")
	}

	publicRefreshes, err := secdat.RelationSuggestRefresh(options, "PUBLIC_URL")
	if err != nil {
		fail("Go SDK public relation refresh failed: %v", err)
	}
	if len(publicRefreshes) != 0 {
		fail("Go SDK public role should not produce refresh suggestions: %#v", publicRefreshes)
	}

	longRefreshes, err := secdat.RelationSuggestRefresh(options, "LONG_PRIMARY")
	if err != nil {
		fail("Go SDK long relation refresh failed: %v", err)
	}
	if len(longRefreshes) != 2 {
		fail("Go SDK long role refresh count mismatch: %#v", longRefreshes)
	}
	assertNoSecretText(compactJSON(longRefreshes), "Go SDK long relation refresh")
	if findRefreshSuggestion(longRefreshes, "sdk-long-refresh", longRole, longRole, longPrimaryKeyref, "leaked-relation-member") == nil {
		fail("missing Go SDK long role self suggestion")
	}
	if findRefreshSuggestion(longRefreshes, "sdk-long-refresh", longRole, "secondary", longSecondaryKeyref, "combination-sensitive-relation") == nil {
		fail("missing Go SDK long role related suggestion")
	}
}
GO

go_build_args=(run)
if test -z "$shared_library_path"; then
    go_build_args+=(-tags secdat_static)
fi
go_build_args+=(. "$root_domain" "$refresh_domain" "$long_role" "$cli_plan")
(cd "$go_harness_dir" && \
    PKG_CONFIG_PATH="$go_pkg_config_dir" \
    LD_LIBRARY_PATH="$build_root/src/.libs:${LD_LIBRARY_PATH:-}" \
    GOCACHE="$work_root/go-cache" \
    "$go_bin" "${go_build_args[@]}")
fi

printf 'PASS SDK exec plan regression\n'
