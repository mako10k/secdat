"""R: Construct explicit legacy store fixtures without production format overrides."""

import argparse
import os
from pathlib import Path
import re
import shutil
from urllib.parse import unquote_to_bytes


V1_MARKER = b"SECDATSTORE1\nformat=v1\nstate=ready\n"
V2_MARKER = b"SECDATSTORE1\nformat=v2\nstate=ready\n"


def escaped_component(value):
    return "".join(
        chr(byte) if byte in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."
        else f"%{byte:02X}"
        for byte in os.fsencode(value)
    )


def store_root(data_home, domain, store="default"):
    """Resolve an exact registered fixture domain, independent of CLI output."""
    state_root = Path(data_home) / "secdat"
    canonical = os.fsencode(Path(domain).resolve())
    registry = state_root / "domains" / "registry" / "by-root"
    matches = [path for path in registry.iterdir() if unquote_to_bytes(path.name) == canonical]
    if len(matches) != 1:
        raise AssertionError(f"expected one registry entry for {domain}, found {matches!r}")
    domain_id = matches[0].read_text(encoding="ascii")
    if re.fullmatch(r"[0-9a-f]{32}", domain_id) is None:
        raise AssertionError(f"invalid fixture domain id: {domain_id!r}")
    return state_root / "domains" / "by-id" / domain_id / "stores" / escaped_component(store)


def create_v1_store(data_home, domain, store="default", *, marked=False):
    """Install a real empty v1 layout; only a provably empty fresh store may be replaced.

    Call this before seeding legacy entries through the ordinary CLI. A newly
    created v2 default store may exist, but its format marker must be its only
    file. Existing populated fixtures are never converted or discarded.
    """
    root = store_root(data_home, domain, store)
    if root.exists():
        allowed_dirs = {
            "entries", "tombstones", "key-meta", "relations", "masks",
            "domain-ent", "objects", "objects/secret",
        }
        for path in root.rglob("*"):
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                raise AssertionError(f"refusing symlink in empty fixture: {path}")
            if path.is_dir() and relative in allowed_dirs:
                continue
            if relative == "format" and path.is_file() and path.read_bytes() in (V1_MARKER, V2_MARKER):
                continue
            raise AssertionError(f"refusing populated or unknown fixture artifact: {path}")
        shutil.rmtree(root)
    root.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    for name in ("entries", "tombstones", "key-meta", "relations"):
        (root / name).mkdir(mode=0o700)
    if marked:
        (root / "format").write_bytes(V1_MARKER)
        (root / "format").chmod(0o600)
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("data_home")
    parser.add_argument("domain")
    parser.add_argument("store", nargs="?", default="default")
    parser.add_argument("--marked", action="store_true")
    args = parser.parse_args()
    create_v1_store(args.data_home, args.domain, args.store, marked=args.marked)
