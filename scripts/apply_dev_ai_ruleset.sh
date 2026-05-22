#!/usr/bin/env bash
# Apply the dev-ai integration ruleset (Copilot-friendly).
# Requires: gh CLI, repository admin on the GitHub repo that contains this checkout
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${repo_root}"
ruleset_file="${repo_root}/.github/rulesets/dev-ai-copilot-integration.json"

if ! command -v gh >/dev/null 2>&1; then
  echo "error: gh CLI is required" >&2
  exit 1
fi

if [[ ! -f "${ruleset_file}" ]]; then
  echo "error: missing ${ruleset_file}" >&2
  exit 1
fi

owner_repo="$(gh repo view --json nameWithOwner -q .nameWithOwner)"
echo "Applying ruleset to ${owner_repo} from ${ruleset_file}"

if gh api "repos/${owner_repo}/rulesets" --jq '.[].name' 2>/dev/null | grep -qx 'dev-ai integration (Copilot-friendly)'; then
  echo "Ruleset already exists. Update it in Settings → Rules → Rulesets, or delete and re-run."
  exit 0
fi

gh api --method POST "repos/${owner_repo}/rulesets" --input "${ruleset_file}"

cat <<'EOF'

Ruleset created.

IMPORTANT: Remove classic branch protection on dev-ai if present:
  Settings → Branches → delete the dev-ai rule

Then retry Copilot on your PR:
  @copilot please try again

EOF
