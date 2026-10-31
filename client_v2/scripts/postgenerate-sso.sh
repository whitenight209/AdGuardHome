#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
npx prettier --write "src/features/sso/api/generated.ts" "src/features/sso/api/model/**/*.ts"
npx eslint --quiet --fix "src/features/sso/api/generated.ts" "src/features/sso/api/model/**/*.ts"
