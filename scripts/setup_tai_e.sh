#!/usr/bin/env bash
set -euo pipefail

# Simple Tai-e setup helper (source build).
# Usage: scripts/setup_tai_e.sh [clone_dir]

TAI_E_ROOT="${HOME}/tai-e-infrastructure"
SRC_DIR="${1:-${TAI_E_ROOT}/source/Tai-e}"
JAR_DIR="${TAI_E_ROOT}/jars"

mkdir -p "${TAI_E_ROOT}"/{jars,configs,benchmarks,results,logs,source}

echo "[info] Tai-e infrastructure: ${TAI_E_ROOT}"
echo "[info] Tai-e source dir: ${SRC_DIR}"

if [[ ! -d "${SRC_DIR}/.git" ]]; then
  echo "[info] Cloning Tai-e repository..."
  git clone https://github.com/pascal-lab/Tai-e.git "${SRC_DIR}"
else
  echo "[info] Tai-e repo already present."
fi

cd "${SRC_DIR}"
echo "[info] Initializing java-benchmarks submodule..."
git submodule update --init --recursive
echo "[info] Building fat JAR with Gradle..."
./gradlew fatJar

JAR_PATH="$(ls "${SRC_DIR}"/build/tai-e-all-*.jar 2>/dev/null | head -n 1)"
if [[ -z "${JAR_PATH}" ]]; then
  JAR_PATH="${SRC_DIR}/build/libs/tai-e-all.jar"
fi
if [[ ! -f "${JAR_PATH}" ]]; then
  echo "[error] Expected a tai-e-all JAR under ${SRC_DIR}/build (or build/libs) but it was not found."
  exit 1
fi

mkdir -p "${JAR_DIR}"
ln -sf "${JAR_PATH}" "${JAR_DIR}/tai-e-all.jar"

echo "[info] Verifying Tai-e JAR..."
java -jar "${JAR_DIR}/tai-e-all.jar" --help >/dev/null

cat <<EOF
[ok] Tai-e installed.
Set TAI_E_HOME:
  export TAI_E_HOME="${JAR_DIR}/tai-e-all.jar"
EOF
