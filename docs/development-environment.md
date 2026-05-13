# secdat Development Environment

This document defines the reproducible development and build environments for secdat.

## Profiles

- `build`: minimum packages for `./autogen.sh`, `./configure`, and `make`
- `dev`: the build profile plus debugger, binding toolchains, and repository-search tools used during implementation work

The canonical entrypoint for host-package setup is [scripts/bootstrap-system.sh](../scripts/bootstrap-system.sh).

## Host bootstrap

Check the minimum build dependencies:

```sh
./scripts/bootstrap-system.sh --profile build --check
```

Install the minimum build dependencies:

```sh
sudo ./scripts/bootstrap-system.sh --profile build --install --assume-yes
```

Install the full development environment:

```sh
sudo ./scripts/bootstrap-system.sh --profile dev --install --assume-yes
```

The script auto-detects Debian-family and Amazon Linux-family systems from `/etc/os-release`.

## Debian-family packages

`build` installs:

- `build-essential`
- `autoconf`
- `automake`
- `libtool`
- `pkg-config`
- `gettext`
- `autopoint`
- `libssl-dev`
- `ca-certificates`
- `git`

`dev` adds:

- `bash`
- `curl`
- `gdb`
- `strace`
- `locales`
- `python3`
- `python3-pip`
- `python3-venv`
- `nodejs`
- `npm`
- `golang-go`
- `cargo`
- `rustc`
- `ripgrep`
- `jq`
- `shellcheck`

## Amazon Linux-family packages

`build` installs:

- `gcc`
- `gcc-c++`
- `make`
- `autoconf`
- `automake`
- `libtool`
- `pkgconf-pkg-config`
- `gettext`
- `gettext-devel`
- `openssl-devel`
- `ca-certificates`
- `git`

`dev` adds:

- `bash`
- `curl`
- `gdb`
- `strace`
- `glibc-langpack-en`
- `glibc-langpack-ja`
- `python3`
- `python3-pip`
- `nodejs`
- `npm`
- `golang`
- `cargo`
- `rust`
- `ripgrep`
- `jq`
- `ShellCheck`

## autogen.sh workflow

[autogen.sh](../autogen.sh) now wraps the dependency checks and can optionally run `configure`.

Examples:

```sh
./autogen.sh --profile build
./autogen.sh --profile build --configure
./autogen.sh --profile dev --check-deps
./autogen.sh --profile dev --install-deps
./autogen.sh --profile build --configure --prefix=/tmp/secdat-prefix
```

Use `--profile build` for CI or release-like toolchains. Use `--profile dev` when working on the C core and language bindings in one environment.

## Dev Container

The repository now ships a VS Code devcontainer under [.devcontainer](../.devcontainer).

- [devcontainer.json](../.devcontainer/devcontainer.json) defines the editor-facing setup
- [Dockerfile.dev](../.devcontainer/Dockerfile.dev) builds the full Debian-family development environment

On first open, VS Code runs:

```sh
./autogen.sh --profile dev --configure
```

That leaves the workspace ready for `make`, `make check`, and binding work without redoing host setup by hand.

## Production / release-like build container

Use [Dockerfile.build](../.devcontainer/Dockerfile.build) when you want a narrower build-only environment.

Debian-family build:

```sh
docker build -f .devcontainer/Dockerfile.build --build-arg BASE_IMAGE=debian:bookworm-slim .
```

Amazon Linux-family build:

```sh
docker build -f .devcontainer/Dockerfile.build --build-arg BASE_IMAGE=amazonlinux:2023 .
```

That image installs only the `build` profile, then runs `./autogen.sh`, `./configure`, and `make` inside the container.

## AI-assisted development tools

The only AI-specific tools recommended for this repository are these VS Code extensions:

- `GitHub.copilot`: inline code completion while editing C, shell, docs, and binding files
- `GitHub.copilot-chat`: repository-aware chat for implementation, review, and command generation inside VS Code

The following non-AI tools are included in the `dev` profile because they make AI-assisted work materially better:

- `ripgrep`: fast repository search for narrowing implementation surfaces and validation targets
- `jq`: inspection of JSON from `gh`, editor tooling, and API responses
- `shellcheck`: static checking for shell scripts such as `autogen.sh` and test/bootstrap scripts
- `gdb` and `strace`: runtime debugging when a generated fix needs verification beyond compilation

## Validation

Typical development validation after bootstrap:

```sh
./autogen.sh --profile dev --configure
make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"
make check
```