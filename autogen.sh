#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH='' cd -- "$(dirname "$0")" && pwd)
BOOTSTRAP_SCRIPT="$SCRIPT_DIR/scripts/bootstrap-system.sh"
PROFILE=build
RUN_CONFIGURE=0
CHECK_DEPS=1
INSTALL_DEPS=0

usage() {
	cat <<'EOF'
Usage: ./autogen.sh [OPTIONS] [-- CONFIGURE_ARGS...]

Options:
  --profile build|dev   Select dependency profile for checks (default: build)
  --build               Alias for --profile build
  --dev                 Alias for --profile dev
  --check-deps          Check system dependencies and exit
  --install-deps        Install missing dependencies for the selected profile
  --no-check-deps       Skip dependency checks before autoreconf
  --configure           Run ./configure after autoreconf
  --help                Show this help

Examples:
  ./autogen.sh --profile build
  ./autogen.sh --profile dev --configure
  ./autogen.sh --profile build --configure --prefix=/tmp/secdat-prefix
EOF
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
		--build)
			PROFILE=build
			;;
		--dev)
			PROFILE=dev
			;;
		--check-deps)
			"$BOOTSTRAP_SCRIPT" --profile "$PROFILE" --check
			exit 0
			;;
		--install-deps)
			INSTALL_DEPS=1
			;;
		--no-check-deps)
			CHECK_DEPS=0
			;;
		--configure)
			RUN_CONFIGURE=1
			;;
		--help|-h)
			usage
			exit 0
			;;
		--)
			shift
			RUN_CONFIGURE=1
			break
			;;
		*)
			RUN_CONFIGURE=1
			break
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

if [ ! -x "$BOOTSTRAP_SCRIPT" ]; then
	printf 'bootstrap helper is missing or not executable: %s\n' "$BOOTSTRAP_SCRIPT" >&2
	exit 1
fi

if [ "$INSTALL_DEPS" = 1 ]; then
	"$BOOTSTRAP_SCRIPT" --profile "$PROFILE" --install
fi

if [ "$CHECK_DEPS" = 1 ]; then
	"$BOOTSTRAP_SCRIPT" --profile "$PROFILE" --check
fi

autoreconf -fi

if [ "$RUN_CONFIGURE" = 1 ]; then
	./configure "$@"
fi
