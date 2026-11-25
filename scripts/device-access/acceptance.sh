#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/../.." && pwd)"

cd "$ROOT_DIR"

python3 -m py_compile scripts/device-access/device_access.py
python3 scripts/device-access/device_access.py selftest

RADIUSD="${RADIUSD:-}"
if [[ -z "$RADIUSD" ]]; then
	if [[ -x "$ROOT_DIR/build/install/sbin/radiusd" ]]; then
		RADIUSD="$ROOT_DIR/build/install/sbin/radiusd"
	elif [[ -x "$ROOT_DIR/build/bin/local/radiusd" ]]; then
		RADIUSD="$ROOT_DIR/build/bin/local/radiusd"
	elif command -v radiusd >/dev/null 2>&1; then
		RADIUSD="$(command -v radiusd)"
	fi
fi

if [[ -n "$RADIUSD" ]]; then
	echo "== FreeRADIUS configuration check =="
	if [[ "$RADIUSD" == "$ROOT_DIR/build/bin/local/radiusd" ]]; then
		"$RADIUSD" -C -d "$ROOT_DIR/raddb" -D "$ROOT_DIR/share/dictionary"
	else
		"$RADIUSD" -C -d "$ROOT_DIR/raddb"
	fi
	echo "PASS | radiusd configuration check"
else
	echo "SKIP | radiusd -C (build FreeRADIUS or set RADIUSD)"
fi
