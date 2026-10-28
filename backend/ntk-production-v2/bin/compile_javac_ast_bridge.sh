#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
JAVAC_BIN="${NTK_JAVAC_BIN:-javac}"
AST_DIR="${ROOT_DIR}/scripts/javac_ast_bridge"
"${JAVAC_BIN}" --release 17 "${AST_DIR}/NtkJavacAstExtractor.java"
echo "Compiled NtkJavacAstExtractor.java with ${JAVAC_BIN} (--release 17)."
