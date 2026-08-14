#!/usr/bin/env bash
# shellcheck disable=SC2016 # Literal metadata probes must not expand template variables.

set -euo pipefail

source_root="${1:-$(cd "$(dirname "$0")/.." && pwd)}"
source_root=$(cd "$source_root" && pwd -P)

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
grep -Fq '## Release candidate review and validation receipts' "$release_workflow" ||
    fail "release workflow does not define the receipt-driven candidate pipeline"
grep -Fq 'bash tests/gettext_catalog_regression.sh "$PWD"' "$release_workflow" ||
    fail "release workflow does not require the pre-freeze gettext check"
grep -Fq 'make -C po update-po' "$release_workflow" ||
    fail "release workflow does not force gettext template and catalog updates"
grep -Fq 'this step does not depend on an earlier configured build.' \
    "$release_workflow" ||
    fail "release workflow depends on a preconfigured tree for gettext updates"
grep -Fq 'Keep `po/secdat.pot` tracked' "$release_workflow" ||
    fail "release workflow does not keep reviewed gettext template metadata"
test -f "$source_root/po/secdat.pot" ||
    fail "tracked gettext template is missing"
if grep -Eq '^po/.*\.pot$' "$source_root/.gitignore"; then
    fail "tracked gettext template is still ignored"
fi
git_root=$(git -C "$source_root" rev-parse --show-toplevel 2>/dev/null || :)
if test -n "$git_root"; then
    git_root=$(cd "$git_root" && pwd -P)
fi
if test "$git_root" = "$source_root"; then
    git -C "$source_root" ls-files --error-unmatch -- po/secdat.pot \
        >/dev/null 2>&1 ||
        fail "gettext template exists but is not tracked"
fi
grep -Eq '^EXTRA_DIST = .*tests/gettext_catalog_regression\.sh' \
    "$source_root/Makefile.am" ||
    fail "gettext catalog regression is not distributed"
grep -Eq '^EXTRA_DIST = .*tests/static_analysis_contract_regression\.sh' \
    "$source_root/Makefile.am" ||
    fail "static analysis contract regression is not distributed"
grep -Eq '^EXTRA_DIST = .*tests/static_analysis_regression\.sh' \
    "$source_root/Makefile.am" ||
    fail "static analysis regression is not distributed"
check_local_recipe=$(sed -n '/^check-local:/,/^pkgconfigdir =/p' \
    "$source_root/Makefile.am")
grep -Fq 'bash $(srcdir)/tests/gettext_catalog_regression.sh' \
    <<<"$check_local_recipe" ||
    fail "make check does not run the gettext catalog regression"
grep -Fq 'bash $(srcdir)/tests/static_analysis_contract_regression.sh' \
    <<<"$check_local_recipe" ||
    fail "make check does not run the static analysis contract regression"
grep -Fq 'bash $(srcdir)/tests/static_analysis_regression.sh' \
    <<<"$check_local_recipe" ||
    fail "make check does not run the static analysis regression"
static_analysis_script="$source_root/tests/static_analysis_regression.sh"
grep -Fq 'jscpd_expected_version="${JSCPD_EXPECTED_VERSION:-4.0.7}"' \
    "$static_analysis_script" ||
    fail "jscpd version is not pinned"
grep -Fq 'lizard_expected_version="${LIZARD_EXPECTED_VERSION:-1.23.0}"' \
    "$static_analysis_script" ||
    fail "lizard version is not pinned"
grep -Fq 'jscpd_duplication_limit="0.34"' "$static_analysis_script" ||
    fail "jscpd duplication ceiling is not pinned"
grep -Fq 'lizard_warning_budget=171' "$static_analysis_script" ||
    fail "lizard warning budget is not pinned"
grep -Fq "candidate_commit=\$(git rev-parse --verify 'HEAD^{commit}')" "$release_workflow" ||
    fail "release workflow does not freeze the candidate commit"
grep -Fq "candidate_tree=\$(git rev-parse --verify 'HEAD^{tree}')" "$release_workflow" ||
    fail "release workflow does not freeze the candidate tree"
grep -Fq 'must not run or rerun full' "$release_workflow" ||
    fail "release workflow does not keep static review separate from full validation"
grep -Fq 'does not rerun a full gate merely to reproduce' "$release_workflow" ||
    fail "release workflow does not require final review to consume valid receipts"
grep -Fq 'Do not overlap full build, check,' "$release_workflow" ||
    fail "release workflow allows full gates to overlap in one worktree"
grep -Fq 'issue #217 exposed a shared-only bug' "$release_workflow" ||
    fail "release workflow does not preserve the shared-only package-shape finding"
grep -Fq 'bind all three receipts to the same candidate' "$release_workflow" ||
    fail "release workflow does not bind all distcheck profiles to one candidate"
grep -Fq 'do not restart the' "$release_workflow" ||
    fail "release workflow does not prevent per-profile review/matrix restarts"
test "$(grep -Fc 'make distcheck DISTCHECK_CONFIGURE_FLAGS' "$release_workflow")" -eq 3 ||
    fail "release workflow does not define exactly the required distcheck profiles"
grep -Fq 'make distcheck DISTCHECK_CONFIGURE_FLAGS=--enable-fuse' "$release_workflow" ||
    fail "release workflow is missing the default FUSE distcheck"
grep -Fq "make distcheck DISTCHECK_CONFIGURE_FLAGS='--enable-fuse --enable-shared --disable-static'" "$release_workflow" ||
    fail "release workflow is missing the shared-only FUSE distcheck"
grep -Fq "make distcheck DISTCHECK_CONFIGURE_FLAGS='--enable-fuse --disable-shared --enable-static'" "$release_workflow" ||
    fail "release workflow is missing the static-only FUSE distcheck"
grep -Fq 'go build -tags secdat_static' "$release_workflow" ||
    fail "release workflow is missing the static-only Go consumer check"
grep -Fq 'main_push_status=$?' "$release_workflow" ||
    fail "release workflow does not capture an ambiguous main push result"
grep -Fq 'tag_push_status=$?' "$release_workflow" ||
    fail "release workflow does not capture an ambiguous tag push result"
grep -Fq 'verify_remote_release_refs()' "$release_workflow" ||
    fail "release workflow does not centralize exact release ref verification"
test "$(grep -Ec '^verify_remote_release_refs$' "$release_workflow")" -eq 2 ||
    fail "release refs are not verified after both tag push and Release creation"
grep -Fq 'test "$remote_tag_object" = "$local_tag_object"' "$release_workflow" ||
    fail "release workflow does not preserve annotated tag object identity"
grep -Fq 'test "$remote_tag_commit" = "$release_commit"' "$release_workflow" ||
    fail "release workflow does not preserve peeled tag commit identity"
grep -Fq 'git remote get-url --push --all origin' "$release_workflow" ||
    fail "release workflow does not freeze the origin push destination"
grep -Fq 'test -n "${candidate_commit:-}"' "$release_workflow" ||
    fail "release workflow does not require the validated candidate commit as input"
grep -Fq 'test -n "${candidate_tree:-}"' "$release_workflow" ||
    fail "release workflow does not require the validated candidate tree as input"
test "$(grep -Fc 'test -z "$(git status --porcelain --untracked-files=normal)"' "$release_workflow")" -eq 2 ||
    fail "release workflow does not recheck a clean worktree before publication"
grep -Fq 'test "$release_commit" = "$candidate_commit"' "$release_workflow" ||
    fail "release workflow does not bind publication to the validated candidate commit"
grep -Fq 'test "$release_tree" = "$candidate_tree"' "$release_workflow" ||
    fail "release workflow does not bind publication to the validated candidate tree"
grep -Fq 'git push "$origin_push_url" HEAD:refs/heads/main' "$release_workflow" ||
    fail "release workflow does not push main to the frozen push destination"
grep -Fq 'git push "$origin_push_url" "${tag_ref}:${tag_ref}"' "$release_workflow" ||
    fail "release workflow does not push the tag to the frozen push destination"
grep -Fq 'git ls-remote --exit-code "$origin_push_url" refs/heads/main' "$release_workflow" ||
    fail "release workflow does not read main back from the frozen push destination"
test "$(grep -Fc 'git ls-remote --exit-code "$origin_push_url"' "$release_workflow")" -eq 2 ||
    fail "release workflow does not read both main and release refs from the frozen push destination"
if grep -Eq 'git push origin|git ls-remote --exit-code origin' "$release_workflow"; then
    fail "release workflow still writes to or reads back from an unfrozen remote name"
fi
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
if grep -Fq '"$OLDPWD/configure"' "$release_workflow"; then
    fail "static release validation reuses a possibly configured source tree"
fi
grep -Fxq 'make dist' "$release_workflow" ||
    fail "static release validation does not create a clean source archive"
grep -Fq 'tar -xzf "$static_archive" -C "$static_source_parent"' \
    "$release_workflow" ||
    fail "static release validation does not extract a clean source tree"
grep -Fq '"$static_source/configure" --disable-shared --enable-static' \
    "$release_workflow" ||
    fail "static release validation does not use the extracted source tree"
grep -Fq 'PKG_CONFIG_PATH= PKG_CONFIG_LIBDIR="$static_pc_dir" pkg-config "$@"' \
    "$release_workflow" ||
    fail "static release validation can fall back to host pkg-config metadata"
grep -Fq 'static_pkg_config --variable=pcfiledir libsecdat' "$release_workflow" ||
    fail "static release validation does not verify staged metadata provenance"
grep -Fq 'static_pkg_config --variable=prefix libsecdat' "$release_workflow" ||
    fail "static release validation does not verify the staged prefix"
grep -Fq 'static_pkg_config --modversion libsecdat' "$release_workflow" ||
    fail "static release validation does not verify the staged version"
grep -Fq 'static_dynamic_section=$(readelf -d "$static_build/consumer")' \
    "$release_workflow" ||
    fail "static release validation does not inspect consumer dependencies"
grep -Fq 'Shared library: [libsecdat.so' "$release_workflow" ||
    fail "static release validation does not reject a shared libsecdat dependency"
grep -Fq 'pkg_config_args=(--static --cflags --libs libsecdat)' \
    "$source_root/tests/install_regression.sh" ||
    fail "installed-consumer regression does not select the static C contract"
grep -Fq 'PKG_CONFIG_SYSROOT_DIR="$sdk_dest"' \
    "$source_root/tests/install_regression.sh" ||
    fail "installed-consumer regression does not validate installed pkg-config paths"
grep -Fq 'PKG_CONFIG_LIBDIR="$installed_pkg_config_dir"' \
    "$source_root/tests/install_regression.sh" ||
    fail "installed-consumer regression can fall back to host pkg-config metadata"
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
