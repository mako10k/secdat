#!/bin/sh
set -eu

PROFILE=build
ACTION=check
ASSUME_YES=0
DISTRO_OVERRIDE=
PRINT_INSTALL_COMMAND=0

usage() {
	cat <<'EOF'
Usage: ./scripts/bootstrap-system.sh [OPTIONS]

Bootstrap host packages for secdat on supported Linux distributions.

Options:
  --profile build|dev       Select the dependency set (default: build)
  --check                   Verify required tools are installed (default)
  --install                 Install the selected dependency set
  --print-install-command   Print the package-manager command and exit
  --distro debian|amazonlinux
                            Override distro-family detection
  --assume-yes              Pass non-interactive approval to the package manager
  --help                    Show this help

Profiles:
  build  Minimum toolchain for ./autogen.sh, ./configure, and make
  dev    Build toolchain plus editors, debuggers, binding toolchains, and AI-friendly CLI tools
EOF
}

normalize_family() {
	case "$1" in
		debian|ubuntu|linuxmint|pop|raspbian)
			printf '%s\n' debian
			return 0
			;;
		amazonlinux|amazon|amzn|amzn2|amzn2023|rhel|centos|rocky|almalinux|fedora)
			printf '%s\n' amazonlinux
			return 0
			;;
		*)
			return 1
			;;
	esac
}

detect_family() {
	if [ -n "$DISTRO_OVERRIDE" ]; then
		if normalize_family "$DISTRO_OVERRIDE"; then
			return 0
		fi
		printf 'unsupported distro override: %s\n' "$DISTRO_OVERRIDE" >&2
		exit 2
	fi

	if [ ! -r /etc/os-release ]; then
		printf 'cannot detect distro family: /etc/os-release is missing\n' >&2
		exit 1
	fi

	# shellcheck disable=SC1091
	. /etc/os-release

	if normalize_family "${ID:-}"; then
		return 0
	fi

	for candidate in ${ID_LIKE:-}; do
		if normalize_family "$candidate"; then
			return 0
		fi
	done

	printf 'unsupported distro family: ID=%s ID_LIKE=%s\n' "${ID:-unknown}" "${ID_LIKE:-unknown}" >&2
	exit 1
}

build_packages_debian() {
	cat <<'EOF'
build-essential
autoconf
automake
libtool
pkg-config
gettext
autopoint
libssl-dev
libjansson-dev
ca-certificates
git
EOF
}

build_packages_amazonlinux() {
	cat <<'EOF'
gcc
gcc-c++
make
autoconf
automake
libtool
pkgconf-pkg-config
gettext
gettext-devel
openssl-devel
jansson-devel
ca-certificates
git
EOF
}

dev_extras_debian() {
	cat <<'EOF'
bash
curl
gdb
strace
locales
libfuse3-dev
python3
python3-pip
python3-venv
nodejs
npm
golang-go
cargo
rustc
ripgrep
jq
shellcheck
EOF
}

dev_extras_amazonlinux() {
	cat <<'EOF'
bash
curl
gdb
strace
glibc-langpack-en
glibc-langpack-ja
fuse3-devel
python3
python3-pip
nodejs
npm
golang
cargo
rust
ripgrep
jq
ShellCheck
EOF
}

package_lines() {
	family="$1"
	case "$family" in
		debian)
			build_packages_debian
			if [ "$PROFILE" = dev ]; then
				dev_extras_debian
			fi
			;;
		amazonlinux)
			build_packages_amazonlinux
			if [ "$PROFILE" = dev ]; then
				dev_extras_amazonlinux
			fi
			;;
	esac
}

package_words() {
	package_lines "$1" | tr '\n' ' '
}

install_command() {
	family="$1"
	packages=$(package_words "$family")
	case "$family" in
		debian)
			printf 'apt-get update && apt-get install %s%s\n' "$( [ "$ASSUME_YES" = 1 ] && printf '%s' '-y ' || printf '' )" "$packages"
			;;
		amazonlinux)
			pkg_tool=dnf
			if ! command -v dnf >/dev/null 2>&1 && command -v yum >/dev/null 2>&1; then
				pkg_tool=yum
			fi
			printf '%s install %s%s\n' "$pkg_tool" "$( [ "$ASSUME_YES" = 1 ] && printf '%s' '-y ' || printf '' )" "$packages"
			;;
	esac
}

check_command() {
	command -v "$1" >/dev/null 2>&1
}

check_build_requirements() {
	missing=0
	for tool in autoreconf autoconf automake libtoolize pkg-config autopoint msgfmt xgettext gcc make git; do
		if ! check_command "$tool"; then
			printf 'missing tool: %s\n' "$tool" >&2
			missing=1
		fi
	done

	if check_command pkg-config && ! pkg-config --exists openssl; then
		printf 'missing pkg-config metadata: openssl\n' >&2
		missing=1
	fi

	return "$missing"
}

check_dev_requirements() {
	missing=0
	for tool in bash curl gdb strace python3 node npm go cargo rustc rg jq shellcheck; do
		if ! check_command "$tool"; then
			printf 'missing dev tool: %s\n' "$tool" >&2
			missing=1
		fi
	done

	return "$missing"
}

check_requirements() {
	if ! check_build_requirements; then
		return 1
	fi
	if [ "$PROFILE" = dev ] && ! check_dev_requirements; then
		return 1
	fi
	return 0
}

install_packages() {
	family="$1"
	if [ "$(id -u)" -ne 0 ]; then
		printf 'installation requires root privileges; rerun with sudo or as root\n' >&2
		exit 1
	fi

	case "$family" in
		debian)
			apt-get update
			if [ "$ASSUME_YES" = 1 ]; then
				package_lines "$family" | xargs apt-get install -y
			else
				package_lines "$family" | xargs apt-get install
			fi
			;;
		amazonlinux)
			if command -v dnf >/dev/null 2>&1; then
				if [ "$ASSUME_YES" = 1 ]; then
					package_lines "$family" | xargs dnf install -y
				else
					package_lines "$family" | xargs dnf install
				fi
			else
				if [ "$ASSUME_YES" = 1 ]; then
					package_lines "$family" | xargs yum install -y
				else
					package_lines "$family" | xargs yum install
				fi
			fi
			;;
	esac
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--profile)
			shift
			if [ "$#" -eq 0 ]; then
				printf 'missing value for --profile\n' >&2
				exit 2
			fi
			PROFILE="$1"
			;;
		--check)
			ACTION=check
			;;
		--install)
			ACTION=install
			;;
		--print-install-command)
			PRINT_INSTALL_COMMAND=1
			;;
		--distro)
			shift
			if [ "$#" -eq 0 ]; then
				printf 'missing value for --distro\n' >&2
				exit 2
			fi
			DISTRO_OVERRIDE="$1"
			;;
		--assume-yes)
			ASSUME_YES=1
			;;
		--help|-h)
			usage
			exit 0
			;;
		*)
			printf 'unknown option: %s\n' "$1" >&2
			usage >&2
			exit 2
			;;
	esac
	shift
done

case "$PROFILE" in
	build|dev)
		;;
	*)
		printf 'unsupported profile: %s\n' "$PROFILE" >&2
		exit 2
		;;
esac

FAMILY=$(detect_family)

if [ "$PRINT_INSTALL_COMMAND" = 1 ]; then
	install_command "$FAMILY"
	exit 0
fi

case "$ACTION" in
	check)
		if check_requirements; then
			printf 'secdat %s dependencies are available for %s\n' "$PROFILE" "$FAMILY"
			exit 0
		fi
		printf '\nInstall them with:\n  %s\n' "$(install_command "$FAMILY")" >&2
		exit 1
		;;
	install)
		install_packages "$FAMILY"
		printf 'installed secdat %s dependencies for %s\n' "$PROFILE" "$FAMILY"
		;;
	esac
