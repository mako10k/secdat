#!/bin/bash
set -u
base=/home/katsumata-m/secdat-release-evidence/v0.11.0/probes
printf 'MAKEFLAGS=%q MFLAGS=%q MAKELEVEL=%q\n' "${MAKEFLAGS-}" "${MFLAGS-}" "${MAKELEVEL-}" > "$base/env.txt"
for mode in inherited clear-mflags clear-both; do
 (
 case "$mode" in clear-mflags) unset MFLAGS;; clear-both) unset MAKEFLAGS MFLAGS;; esac
 make -s --no-print-directory -C /home/katsumata-m/secdat-release-0.11.0/secdat-0.11.0/_build/sub -f Makefile -f - print-configured-paths <<'MAKE_EOF'
print-configured-paths:
	@printf '%s\n' '$(prefix)' '$(bindir)' '$(libdir)' '$(includedir)' '$(localedir)'
MAKE_EOF
 ) > "$base/$mode.stdout" 2> "$base/$mode.stderr"
 printf '%s rc=%s\n' "$mode" "$?"
done
