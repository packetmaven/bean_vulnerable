#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${HOME}/.local/bin"

mkdir -p "${TARGET_DIR}"

ln -sf "${ROOT}/bean_vuln" "${TARGET_DIR}/bean_vuln"
ln -sf "${ROOT}/bean_vuln2" "${TARGET_DIR}/bean_vuln2"
ln -sf "${ROOT}/bean-vuln" "${TARGET_DIR}/bean-vuln"
ln -sf "${ROOT}/bean-vuln2" "${TARGET_DIR}/bean-vuln2"

echo "Installed CLI wrappers to ${TARGET_DIR}"
if [[ ":${PATH}:" != *":${TARGET_DIR}:"* ]]; then
  echo "Add to PATH to use globally:"
  echo "  export PATH=\"${TARGET_DIR}:\$PATH\""
fi
