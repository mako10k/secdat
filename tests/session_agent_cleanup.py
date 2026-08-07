#!/usr/bin/env python3

import os
import re
import signal
import socket
import stat
import sys
import time
from pathlib import Path


def fail(message):
    print(f"FAIL: {message}", file=sys.stderr)
    return 1


def runtime_dir_for_pid(pid):
    try:
        entries = (Path("/proc") / str(pid) / "environ").read_bytes().split(b"\0")
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return None
    prefix = b"XDG_RUNTIME_DIR="
    for entry in entries:
        if entry.startswith(prefix):
            return Path(os.fsdecode(entry[len(prefix) :]))
    return None


def process_is_owned(pid, test_root):
    runtime_dir = runtime_dir_for_pid(pid)
    if runtime_dir is None:
        return False
    try:
        runtime_dir.relative_to(test_root)
    except ValueError:
        return False
    try:
        return (Path("/proc") / str(pid) / "comm").read_text().strip() == "secdat"
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return False


def owned_pids(test_root):
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return set()
    result = set()
    for entry in proc_root.iterdir():
        if entry.name.isdigit():
            pid = int(entry.name)
            if process_is_owned(pid, test_root):
                result.add(pid)
    return result


def socket_command(socket_path, command):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(0.5)
        client.connect(str(socket_path))
        client.sendall(command)
        return client.recv(256)


def tracked_socket_paths(test_root):
    try:
        candidates = list(test_root.rglob("agent-*.sock"))
    except OSError:
        return []
    result = []
    for candidate in candidates:
        try:
            if stat.S_ISSOCK(candidate.stat().st_mode):
                result.append(candidate)
        except (FileNotFoundError, OSError):
            continue
    return result


def wait_for_exit(test_root, tracked_pids, seconds):
    deadline = time.monotonic() + seconds
    while True:
        remaining = {
            pid for pid in tracked_pids | owned_pids(test_root)
            if process_is_owned(pid, test_root)
        }
        if not remaining or time.monotonic() >= deadline:
            return remaining
        time.sleep(0.02)


def main():
    if len(sys.argv) != 2:
        return fail("usage: session_agent_cleanup.py TEST_ROOT")
    test_root = Path(sys.argv[1])
    if not test_root.is_absolute():
        return fail(f"session test root is not absolute: {test_root}")

    tracked_pids = owned_pids(test_root)
    for socket_path in tracked_socket_paths(test_root):
        try:
            response = socket_command(socket_path, b"CAPS\n")
            match = re.fullmatch(rb"OK \d+ \d+ pid=(\d+)\n", response)
            if match is not None:
                tracked_pids.add(int(match.group(1)))
        except OSError:
            pass
        try:
            socket_command(socket_path, b"CLEAR\n")
        except OSError:
            pass

    remaining = wait_for_exit(test_root, tracked_pids, 5.0)
    if remaining:
        for pid in remaining:
            if process_is_owned(pid, test_root):
                try:
                    os.kill(pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
        remaining = wait_for_exit(test_root, remaining, 2.0)
    if remaining:
        return fail(
            "test-owned session agents did not exit: "
            + ", ".join(str(pid) for pid in sorted(remaining))
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
