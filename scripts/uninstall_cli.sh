#!/usr/bin/env bash
set -euo pipefail

TARGET_DIR="${HOME}/.local/bin"

rm -f "${TARGET_DIR}/bean_vuln" "${TARGET_DIR}/bean_vuln2"
rm -f "${TARGET_DIR}/bean-vuln" "${TARGET_DIR}/bean-vuln2"

echo "Removed CLI wrappers from ${TARGET_DIR}"
