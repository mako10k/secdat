#!/usr/bin/env bash
# shellcheck disable=SC2016 # Literal metadata probes must not expand template variables.

set -euo pipefail

source_root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

expect_equal() {
    local label="$1"
    local actual="$2"
    local expected="$3"
    if test "$actual" != "$expected"; then
        fail "$label is '$actual', expected '$expected'"
    fi
}

project_version=$(sed -n 's/^AC_INIT(\[secdat\], \[\([^]]*\)\].*/\1/p' "$source_root/configure.ac")
test -n "$project_version" || fail "could not read project version from configure.ac"

node_version=$(sed -n 's/^  "version": "\([^"]*\)",/\1/p' "$source_root/bindings/node/package.json" | head -n 1)
python_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$source_root/bindings/python/pyproject.toml" | head -n 1)
rust_version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$source_root/bindings/rust/Cargo.toml" | head -n 1)
rust_lock_version=$(awk '
    $0 == "name = \"secdat-sdk\"" { found = 1; next }
    found && /^version = / { sub(/^version = "/, ""); sub(/"$/, ""); print; exit }
' "$source_root/bindings/rust/Cargo.lock")
rust_native_minimum=$(sed -n 's/.*atleast_version("\([^"]*\)").*/\1/p' "$source_root/bindings/rust/build.rs")

expect_equal "Node package version" "$node_version" "$project_version"
expect_equal "Python package version" "$python_version" "$project_version"
expect_equal "Rust package version" "$rust_version" "$project_version"
expect_equal "Rust lockfile version" "$rust_lock_version" "$project_version"
expect_equal "Rust native dependency minimum" "$rust_native_minimum" "$project_version"

node_lock_versions=$(sed -n 's/^ *"version": "\([^"]*\)",/\1/p' "$source_root/bindings/node/package-lock.json" | head -n 2)
while IFS= read -r version; do
    expect_equal "Node lockfile package version" "$version" "$project_version"
done <<<"$node_lock_versions"

release_notes="docs/release-notes/v${project_version}.md"
test -f "$source_root/$release_notes" || fail "missing $release_notes"
grep -Fq "# secdat v${project_version} Release Notes" "$source_root/$release_notes" ||
    fail "$release_notes has the wrong title"
grep -Fq "$release_notes" "$source_root/Makefile.am" ||
    fail "$release_notes is not included in Makefile.am EXTRA_DIST"

grep -Fq "\"secdat $project_version\"" "$source_root/docs/secdat.1" ||
    fail "docs/secdat.1 version does not match $project_version"
grep -Fq "\"secdat $project_version\"" "$source_root/docs/secdat-fuse.1" ||
    fail "docs/secdat-fuse.1 version does not match $project_version"
grep -Fq "Project-Id-Version: secdat $project_version" "$source_root/po/ja.po" ||
    fail "po/ja.po project version does not match $project_version"
grep -Fq "Version: $project_version" "$source_root/tests/sdk_regression.sh" ||
    fail "SDK pkg-config fixture does not match $project_version"
grep -Fq 'Libs.private: $sdk_private_link_flags_text' "$source_root/tests/sdk_regression.sh" ||
    fail "SDK pkg-config fixture does not preserve the private static link contract"
grep -Fxq 'Libs: -L${libdir} -lsecdat' "$source_root/libsecdat.pc.in" ||
    fail "libsecdat.pc.in exposes private dependencies to shared consumers"
grep -Fxq 'Libs.private: @SECDAT_PRIVATE_LIBS@' "$source_root/libsecdat.pc.in" ||
    fail "libsecdat.pc.in does not declare the private static link closure"
grep -Fxq 'Cflags: -I${includedir}' "$source_root/libsecdat.pc.in" ||
    fail "libsecdat.pc.in exposes private dependency headers"
if grep -Fq 'Requires.private:' "$source_root/libsecdat.pc.in"; then
    fail "libsecdat.pc.in exposes private dependency Cflags"
fi

release_workflow="$source_root/docs/release-workflow.md"
grep -Fq 'make distcheck DISTCHECK_CONFIGURE_FLAGS=--enable-fuse' "$release_workflow" ||
    fail "release workflow is missing the default FUSE distcheck"
grep -Fq "make distcheck DISTCHECK_CONFIGURE_FLAGS='--enable-fuse --disable-shared --enable-static'" "$release_workflow" ||
    fail "release workflow is missing the static-only FUSE distcheck"
grep -Fq 'go build -tags secdat_static' "$release_workflow" ||
    fail "release workflow is missing the static-only Go consumer check"
grep -Fq 'main_push_status=$?' "$release_workflow" ||
    fail "release workflow does not capture an ambiguous main push result"
grep -Fq 'tag_push_status=$?' "$release_workflow" ||
    fail "release workflow does not capture an ambiguous tag push result"
grep -Fq 'git remote get-url --push --all origin' "$release_workflow" ||
    fail "release workflow does not freeze the origin push destination"
grep -Fq 'repos/$release_repo/releases/tags/$release_tag' "$release_workflow" ||
    fail "release preflight is not bound to the frozen GitHub repository"
test "$(grep -Fc -- '--repo "$release_repo_ref"' "$release_workflow")" -eq 2 ||
    fail "GitHub Release create/readback are not both bound to the frozen repository"
grep -Fq 'git cat-file blob "$release_notes_blob" >"$frozen_release_notes"' "$release_workflow" ||
    fail "release notes are not materialized from the release commit blob"
grep -Fq -- '--notes-file "$frozen_release_notes"' "$release_workflow" ||
    fail "GitHub Release creation does not use commit-bound notes"
grep -Fq -- '--rawfile body "$frozen_release_notes"' "$release_workflow" ||
    fail "GitHub Release readback does not use commit-bound notes"
grep -Fq 'pkg-config --static --cflags --libs libsecdat' "$release_workflow" ||
    fail "release workflow is missing the static-only C consumer command"
grep -Fq 'pkg_config_args=(--static --cflags --libs libsecdat)' \
    "$source_root/tests/install_regression.sh" ||
    fail "installed-consumer regression does not select the static C contract"
grep -Fq 'PKG_CONFIG_SYSROOT_DIR="$default_dest"' \
    "$source_root/tests/install_regression.sh" ||
    fail "installed-consumer regression does not validate installed pkg-config paths"
grep -Fq 'gh release create "$release_tag"' "$release_workflow" ||
    fail "release workflow is missing the one GitHub Release create command"
grep -Fq 'tagName,name,body,isDraft,isPrerelease,targetCommitish,assets,url' "$release_workflow" ||
    fail "release workflow is missing complete GitHub Release readback fields"
grep -Fq 'Do not retry create' "$release_workflow" ||
    fail "release workflow does not prohibit blind GitHub Release retries"
for test_script in "$source_root"/tests/*.sh; do
    test "$test_script" = "$source_root/tests/release_metadata_regression.sh" && continue
    if grep -Fq -- '-lsecdat -lssl' "$test_script"; then
        fail "$test_script bypasses the libsecdat static link contract"
    fi
done

required_binding_files='
bindings/README.md
bindings/go/README.md
bindings/go/go.mod
bindings/go/secdat/pkg_config_shared.go
bindings/go/secdat/pkg_config_static.go
bindings/go/secdat/secdat.go
bindings/node/README.md
bindings/node/binding.gyp
bindings/node/index.js
bindings/node/package-lock.json
bindings/node/package.json
bindings/node/src/addon.cc
bindings/python/README.md
bindings/python/pyproject.toml
bindings/python/secdat_sdk.py
bindings/rust/Cargo.lock
bindings/rust/Cargo.toml
bindings/rust/README.md
bindings/rust/build.rs
bindings/rust/src/lib.rs
'
while IFS= read -r binding_file; do
    test -z "$binding_file" && continue
    test -f "$source_root/$binding_file" || fail "release source is missing $binding_file"
    grep -Fq "$binding_file" "$source_root/Makefile.am" ||
        fail "$binding_file is not included in Makefile.am distribution metadata"
done <<<"$required_binding_files"

printf 'PASS release metadata regression (%s)\n' "$project_version"
