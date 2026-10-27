#!/usr/bin/env bash
#
# OpenSSL 1.0.2zs Unofficial Security Hardening Patchset Wrapper
# Intelligently detects vendor baseline (1.0.2zl enterprise or 1.0.2u public)
# and delegates to the appropriate modular patch engine.
# Maintains backward compatibility with existing automated CI/CD and deployment hooks.
#
# Author / Maintainer : alsyundawy (༺ Initial H ༻) <alsyundawy@gmail.com>
# Website             : https://www.alsyundawy.com
# GitHub              : https://github.com/alsyundawy
# Location            : DKI Jakarta, Indonesia
#

set -Eeuo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Detect source tree version from crypto/opensslv.h if present
TARGET_SCRIPT=""
if [[ -f "${SCRIPT_DIR}/crypto/opensslv.h" ]]; then
	if grep -q "1.0.2zl" "${SCRIPT_DIR}/crypto/opensslv.h" 2>/dev/null; then
		TARGET_SCRIPT="${SCRIPT_DIR}/patch-openssl-1.0.2zl-to-1.0.2zs.sh"
	elif grep -q "1.0.2zs" "${SCRIPT_DIR}/crypto/opensslv.h" 2>/dev/null; then
		TARGET_SCRIPT="${SCRIPT_DIR}/patch-openssl-1.0.2zl-to-1.0.2zs.sh"
	fi
fi

if [[ -z "${TARGET_SCRIPT}" || ! -f "${TARGET_SCRIPT}" ]]; then
	if [[ -f "${SCRIPT_DIR}/patch-openssl-1.0.2u-to-1.0.2zs.sh" ]]; then
		TARGET_SCRIPT="${SCRIPT_DIR}/patch-openssl-1.0.2u-to-1.0.2zs.sh"
	elif [[ -f "${SCRIPT_DIR}/patch-openssl-1.0.2zl-to-1.0.2zs.sh" ]]; then
		TARGET_SCRIPT="${SCRIPT_DIR}/patch-openssl-1.0.2zl-to-1.0.2zs.sh"
	else
		TARGET_SCRIPT="${SCRIPT_DIR}/patch-openssl-1.0.2u-to-1.0.2zr.sh"
	fi
fi

if [[ ! -x ${TARGET_SCRIPT} ]]; then
	chmod +x "${TARGET_SCRIPT}" 2>/dev/null || true
fi

exec "${TARGET_SCRIPT}" "$@"
