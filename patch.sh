#!/usr/bin/env bash
#
# OpenSSL 1.0.2zr Unofficial Security Hardening Patchset Wrapper
# Delegates directly to the modular patch engine patch-openssl-1.0.2u-to-1.0.2zr.sh.
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
TARGET_SCRIPT="${SCRIPT_DIR}/patch-openssl-1.0.2u-to-1.0.2zr.sh"

if [[ ! -x ${TARGET_SCRIPT} ]]; then
	chmod +x "${TARGET_SCRIPT}" 2>/dev/null || true
fi

exec "${TARGET_SCRIPT}" "$@"
