# secdat Release Workflow

This document captures the concrete steps for cutting a release tag and preparing distributable artifacts for `libsecdat` and the language bindings.

## Scope

- the core C project version is still sourced from `configure.ac`
- binding package versions currently track the same version as the core project
- release tags should use the form `vX.Y.Z`

## Before tagging

1. update the version in `configure.ac` and the binding manifests that carry an explicit version:
   - `bindings/node/package.json`
   - `bindings/python/pyproject.toml`
   - `bindings/rust/Cargo.toml`
   - the Node and Rust lockfiles
   - the Rust `libsecdat` minimum in `bindings/rust/build.rs`
   - the manual and gettext project-version headers
2. when the public C SDK changes, update libtool `-version-info` according to
   the compatibility of the change and verify the resulting SONAME
3. regenerate build metadata when the autotools inputs changed:
   - `autoreconf -fi`
   - `./configure`
4. run the project validation:
   - `bash tests/release_metadata_regression.sh "$PWD"`
   - `make check`
   - `make distcheck DISTCHECK_CONFIGURE_FLAGS=--enable-fuse`
   - `make distcheck DISTCHECK_CONFIGURE_FLAGS='--enable-fuse --disable-shared --enable-static'`
5. run installed-consumer validation for published artifacts:
   - `PKG_CONFIG_PATH=$PWD pkg-config --cflags --libs libsecdat`
   - compile and run a shared C consumer using `pkg-config --cflags --libs libsecdat`
   - compile and run a static-only C consumer using `pkg-config --static --cflags --libs libsecdat`
   - `(cd bindings/python && python3 -m pip wheel . --no-deps -w /tmp/secdat-python-wheel)`
   - `prefix=$(mktemp -d) && ./configure --prefix="$prefix" && make && make install`
   - `LD_LIBRARY_PATH="$prefix/lib" SECDAT_SDK_LIBRARY="$prefix/lib/libsecdat.so" PYTHONPATH="$PWD/bindings/python" python3 -c 'from secdat_sdk import Secdat; Secdat()'`
   - `(cd bindings/rust && PKG_CONFIG_PATH="$prefix/lib/pkgconfig" cargo check)`
   - `(cd bindings/node && PKG_CONFIG_PATH="$prefix/lib/pkgconfig" npm run build)`
   - `node_pkg=$(cd bindings/node && npm pack --silent) && tmp_consumer=$(mktemp -d) && cp "bindings/node/$node_pkg" "$tmp_consumer/" && (cd "$tmp_consumer" && npm init -y && PKG_CONFIG_PATH="$prefix/lib/pkgconfig" LD_LIBRARY_PATH="$prefix/lib" npm install "./$node_pkg" && node -e "require('secdat-sdk-node')")`
   - `(cd bindings/go && PKG_CONFIG_PATH="$prefix/lib/pkgconfig" go build ./...)`
   - `(cd bindings/node && npm pack --dry-run)`
   - `(cd bindings/rust && PKG_CONFIG_PATH="$prefix/lib/pkgconfig" cargo package --allow-dirty)`

## Tagging

After the tree is clean and the release contents are committed, publish and
read back `main` before creating the release tag:

```sh
set -eu
release_tag=vX.Y.Z
release_subject="secdat $release_tag"
release_commit=$(git rev-parse --verify 'HEAD^{commit}')
origin_push_urls=$(git remote get-url --push --all origin)
test "$(printf '%s\n' "$origin_push_urls" | wc -l)" -eq 1
origin_push_url=$origin_push_urls
release_host=github.com
case "$origin_push_url" in
  https://github.com/*) release_repo=${origin_push_url#https://github.com/} ;;
  ssh://git@github.com/*) release_repo=${origin_push_url#ssh://git@github.com/} ;;
  git@github.com:*) release_repo=${origin_push_url#git@github.com:} ;;
  *) echo "origin push URL is not a supported GitHub URL" >&2; exit 1 ;;
esac
release_repo=${release_repo%.git}
case "$release_repo" in
  */*) ;;
  *) echo "origin does not identify owner/repository" >&2; exit 1 ;;
esac
case "$release_repo" in
  */*/*) echo "origin has an invalid GitHub repository path" >&2; exit 1 ;;
esac
release_repo_ref="$release_host/$release_repo"

set +e
git push origin HEAD:refs/heads/main
main_push_status=$?
set -e
set +e
remote_main_refs=$(git ls-remote --exit-code origin refs/heads/main)
main_readback_status=$?
set -e
test "$main_readback_status" -eq 0
remote_main=$(printf '%s\n' "$remote_main_refs" |
  awk '$2 == "refs/heads/main" { print $1 }')
test "$remote_main" = "$release_commit"
if test "$main_push_status" -ne 0; then
  echo "main push returned $main_push_status; exact readback accepted" >&2
fi

git tag -a "$release_tag" "$release_commit" -m "$release_subject"
tag_ref="refs/tags/$release_tag"
local_tag_object=$(git rev-parse --verify "${tag_ref}^{tag}")
test "$(git rev-parse --verify "${tag_ref}^{commit}")" = "$release_commit"
test "$(git for-each-ref --format='%(contents:subject)' "$tag_ref")" = \
  "$release_subject"

set +e
git push origin "${tag_ref}:${tag_ref}"
tag_push_status=$?
set -e
set +e
remote_tag_refs=$(git ls-remote --exit-code origin \
  "$tag_ref" "${tag_ref}^{}")
tag_readback_status=$?
set -e
test "$tag_readback_status" -eq 0
remote_tag_object=$(printf '%s\n' "$remote_tag_refs" |
  awk -v ref="$tag_ref" '$2 == ref { print $1 }')
remote_tag_commit=$(printf '%s\n' "$remote_tag_refs" |
  awk -v ref="${tag_ref}^{}" '$2 == ref { print $1 }')
test "$remote_tag_object" = "$local_tag_object"
test "$remote_tag_commit" = "$release_commit"
if test "$tag_push_status" -ne 0; then
  echo "tag push returned $tag_push_status; exact readback accepted" >&2
fi

# Ensure main did not move while the tag was being published.
remote_main=$(git ls-remote --exit-code origin refs/heads/main |
  awk '$2 == "refs/heads/main" { print $1 }')
test "$remote_main" = "$release_commit"
```

If the tag should point at a release-specific commit, create and verify that commit before tagging.
After an ambiguous push result, perform the SHA readback without blindly retrying;
stop without forcing or moving a ref unless every expected SHA matches.

## Publishing the GitHub Release

After the remote tag object and peeled commit have been verified, derive and
freeze every GitHub Release input from the same release values. This project
currently uploads no explicit Release assets; GitHub's automatically generated
source archives are not entries in the Release API `assets` array.

```sh
set -eu
release_title=$release_subject
release_target=$release_commit
release_notes_path="docs/release-notes/$release_tag.md"
release_expected_asset_count=0

test "$(git rev-parse --verify "refs/tags/$release_tag^{commit}")" = \
  "$release_target"
release_notes_blob=$(git rev-parse --verify \
  "$release_target:$release_notes_path")
test "$(git cat-file -t "$release_notes_blob")" = blob
git diff --quiet "$release_target" -- "$release_notes_path"
frozen_release_notes=$(mktemp)
git cat-file blob "$release_notes_blob" >"$frozen_release_notes"
test "$(git hash-object "$frozen_release_notes")" = "$release_notes_blob"
release_notes_sha256=$(sha256sum "$frozen_release_notes" | awk '{ print $1 }')
test -n "$release_notes_sha256"

# A conclusive 404 is the only preflight result that authorizes the one write.
release_preflight=$(mktemp)
set +e
secdat exec -- gh api --include \
  --hostname "$release_host" \
  "repos/$release_repo/releases/tags/$release_tag" >"$release_preflight"
release_preflight_status=$?
set -e
if test "$release_preflight_status" -eq 0; then
  echo "release already exists; stopping before create" >&2
  exit 1
fi
test "$release_preflight_status" -eq 1
grep -Eq '^HTTP/[0-9.]+ 404 Not Found\r?$' "$release_preflight"

# Maximum external writes: this one create command and no automatic retry.
set +e
secdat exec -- gh release create "$release_tag" \
  --repo "$release_repo_ref" \
  --verify-tag \
  --target "$release_target" \
  --title "$release_title" \
  --notes-file "$frozen_release_notes"
release_create_status=$?
set -e

# Read back even when create returned an error or timed out. Never resend it.
release_json=$(mktemp)
secdat exec -- gh release view "$release_tag" \
  --repo "$release_repo_ref" \
  --json tagName,name,body,isDraft,isPrerelease,targetCommitish,assets,url \
  >"$release_json"
jq -e \
  --arg tag "$release_tag" \
  --arg title "$release_title" \
  --arg target "$release_target" \
  --argjson asset_count "$release_expected_asset_count" \
  --rawfile body "$frozen_release_notes" '
    .tagName == $tag and
    .name == $title and
    .body == $body and
    .isDraft == false and
    .isPrerelease == false and
    .targetCommitish == $target and
    (.assets | length) == $asset_count and
    (.url | type == "string" and length > 0)
  ' "$release_json"

if test "$release_create_status" -ne 0; then
  echo "create returned $release_create_status; exact readback accepted" >&2
fi

# Reconfirm that publication did not move either release ref.
remote_main=$(git ls-remote --exit-code origin refs/heads/main |
  awk '$2 == "refs/heads/main" { print $1 }')
remote_tag_commit=$(git ls-remote --exit-code origin \
  "refs/tags/$release_tag^{}" |
  awk -v ref="refs/tags/$release_tag^{}" '$2 == ref { print $1 }')
test "$remote_main" = "$release_commit"
test "$remote_tag_commit" = "$release_commit"
```

If preflight is ambiguous, create readback is absent or mismatched, or any
release field differs, stop. Do not retry create or automatically edit, upload,
delete, republish, or move the tag; those are separate reviewed writes.

## C SDK packaging

For installable native consumers, the release should provide:

- the `libsecdat` shared library
- the installed public header `secdat-sdk.h`
- the generated `libsecdat.pc` pkg-config file

Local release verification from a clean checkout:

```sh
./autogen.sh
./configure --prefix=/tmp/secdat-prefix
make
make install
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig pkg-config --cflags --libs libsecdat
```

The command above is the shared-library C contract. For a static-only install,
use the private dependency closure exposed by `pkg-config --static` and compile
against an isolated prefix:

```sh
static_prefix=$(mktemp -d)
static_build=$(mktemp -d)
(
  cd "$static_build"
  "$OLDPWD/configure" --disable-shared --enable-static \
    --prefix="$static_prefix"
  make
  make install
)
test -f "$static_prefix/lib/libsecdat.a"
test ! -e "$static_prefix/lib/libsecdat.so"
static_pc_dir="$static_prefix/lib/pkgconfig"
test -f "$static_pc_dir/libsecdat.pc"
static_pkg_config() {
  PKG_CONFIG_PATH= PKG_CONFIG_LIBDIR="$static_pc_dir" pkg-config "$@"
}
test "$(static_pkg_config --variable=pcfiledir libsecdat)" = "$static_pc_dir"
test "$(static_pkg_config --variable=prefix libsecdat)" = "$static_prefix"
static_build_version=$("$static_build/src/secdat" --version | sed -n '1s/^secdat //p')
test -n "$static_build_version"
test "$(static_pkg_config --modversion libsecdat)" = "$static_build_version"
cat >"$static_build/consumer.c" <<'EOF'
#include <secdat-sdk.h>
int main(void) { secdat_sdk_free(0); return 0; }
EOF
static_cflags_text=$(static_pkg_config --cflags libsecdat)
static_libs_text=$(static_pkg_config --static --libs libsecdat)
case " $static_cflags_text " in
  *" -I$static_prefix/include "*) ;;
  *) echo "staged libsecdat Cflags were not selected" >&2; exit 1 ;;
esac
case " $static_libs_text " in
  *" -L$static_prefix/lib "*) ;;
  *) echo "staged libsecdat Libs were not selected" >&2; exit 1 ;;
esac
read -r -a static_cflags <<EOF
$static_cflags_text
EOF
read -r -a static_libs <<EOF
$static_libs_text
EOF
cc "${static_cflags[@]}" "$static_build/consumer.c" \
  -o "$static_build/consumer" "${static_libs[@]}"
static_dynamic_section=$(readelf -d "$static_build/consumer")
case "$static_dynamic_section" in
  *"Shared library: [libsecdat.so"*)
    echo "static consumer depends on shared libsecdat" >&2
    exit 1
    ;;
esac
"$static_build/consumer"
```

## Binding publication notes

### Python

Build the wheel from `bindings/python`:

```sh
python3 -m pip wheel . --no-deps -w dist
```

The package is a thin wrapper around an installed `libsecdat` shared library. Runtime users may need `SECDAT_SDK_LIBRARY` when the loader cannot locate `libsecdat` automatically.

### Rust

Check and package from `bindings/rust`:

```sh
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig cargo check
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig cargo package --allow-dirty
```

The crate now uses `pkg-config` in `build.rs`, so the target environment must expose `libsecdat.pc` during builds.

### Node

Build and inspect the package from `bindings/node`:

```sh
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig npm run build
npm pack --dry-run
```

The current package assumes the target system can build the N-API addon against an installed `libsecdat` exposed through `pkg-config`.

### Go

The Go binding is distributed as a module rooted at `bindings/go` and validated with:

```sh
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig go build ./...
```

The default command uses shared `libsecdat`. For a static-only installation,
select the private pkg-config link closure explicitly:

```sh
PKG_CONFIG_PATH=/tmp/secdat-prefix/lib/pkgconfig go build -tags secdat_static ./...
```

The tag covers linking against static `libsecdat.a`; it does not guarantee a
fully static executable across all system dependencies.

If a public module release is needed, publish tags that are valid for the `bindings/go` submodule path before documenting a `go get` flow.

## Release checklist

- versions updated consistently
- tree clean after validation
- `make check` passed
- default/shared-capable and static-only FUSE-enabled `make distcheck` passed
- ABI SONAME/export checks passed
- package-shape checks passed
- tag created and pushed
- GitHub Release published and read back
- release notes mention C SDK changes and binding/API additions
