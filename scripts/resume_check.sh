#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_ROOT="/root/ShieldMendAi"

if [[ "$(pwd -P)" != "${EXPECTED_ROOT}" ]]; then
  echo "ERROR: run this script from ${EXPECTED_ROOT}" >&2
  exit 1
fi

echo "Workspace: $(pwd -P)"
echo "Branch: $(git branch --show-current)"
echo
echo "Git status:"
git status --short --branch
echo
echo "Latest five commits:"
git log -5 --oneline --decorate
echo
echo "Codex handoff:"
sed -n '1,240p' docs/CODEX_HANDOFF.md
echo
echo "Manifest validation:"
python3 -m json.tool extraction_manifest.json >/dev/null
echo "extraction_manifest.json: valid JSON"
echo
echo "Task markers in public workspace:"
marker_pattern='(TO''DO|FIX''ME)'
if ! rg -n --hidden \
  --glob '!.git/**' \
  --glob '!*.log' \
  --glob '!reports/**' \
  --glob '!state/**' \
  "${marker_pattern}" "${EXPECTED_ROOT}"; then
  echo "None found."
fi
echo
echo "Git remotes:"
git remote -v
