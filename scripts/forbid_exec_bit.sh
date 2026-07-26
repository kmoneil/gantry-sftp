#!/usr/bin/env bash
# Reject files recorded as executable in the git INDEX.
#
# Index-based, not filesystem-based, on purpose: /workspace is a `fakeowner` mount that
# reports every file as executable, so a `test -x` check fails on everything and teaches
# people to skip the hook. Git's index mode is the thing that actually gets committed, and
# it is what a reviewer on another machine will see.
#
# The allowlist exists because one file genuinely needs the bit: the SSH_ASKPASS helper is
# exec'd by ssh(1) and does not work without it. Dropping the whole check to accommodate
# that one file is the trade this allowlist refuses to make.
set -euo pipefail

ALLOWED=(
  # "src/gantry_sftp/transport/_askpass.py"  # uncomment when the helper lands
)

mapfile -t executables < <(git ls-files --stage | awk '$1 == "100755" { print $4 }')

violations=()
for file in "${executables[@]:-}"; do
  [[ -z "$file" ]] && continue
  allowed=false
  for permitted in "${ALLOWED[@]:-}"; do
    if [[ "$file" == "$permitted" ]]; then
      allowed=true
      break
    fi
  done
  if [[ "$allowed" == false ]]; then
    violations+=("$file")
  fi
done

if ((${#violations[@]} > 0)); then
  echo "error: files are marked executable in the git index:" >&2
  printf '  %s\n' "${violations[@]}" >&2
  echo >&2
  echo "Fix with:  git update-index --chmod=-x <file>" >&2
  echo "If a file genuinely needs the bit, add it to ALLOWED in $0." >&2
  exit 1
fi
