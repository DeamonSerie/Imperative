#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# Check only source files, not this script or lockfiles or workflows
# Look for actual sha2 usage in source
if grep -RInE '\bsha2\b|SHA2' --include='*.rs' --include='*.toml' --exclude-dir=target . | grep -v 'Cargo.lock' | grep -v 'scripts/check_no_sha2.sh' ; then
  echo "ERROR: forbidden sha2/SHA2 reference found" >&2
  exit 1
fi
echo "OK: no sha2/SHA2 references"
