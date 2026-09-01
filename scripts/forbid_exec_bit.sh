#!/usr/bin/env bash
# Reject files recorded as executable in the git INDEX.
#
# Index-based, not filesystem-based, on purpose: /workspace is a `fakeowner` mount that
# reports every file as executable, so a `test -x` check fails on everything and teaches
# people to skip the hook. Git's index mode is the thing that actually gets committed, and
# it is what a reviewer on another machine will see.
#
# The allowlist was reserved for the SSH_ASKPASS helper, which is exec'd by ssh(1) and cannot
# work without the bit. It is still empty, and that is now a design outcome rather than a
# pending task: `password=` shipped in 0.9 and writes its helper to a 0700 temporary directory
# at connect time instead of shipping an executable. Nothing in the distribution needs the bit,
# so no file needs an exception -- and there is no fixed path on disk for another process owned
# by this user to find. Keep it empty unless something genuinely has to ship executable.
#
# Written for bash 3.2, which is the /bin/bash macOS ships and what this hook runs under there.
# The first spelling used `mapfile`, a bash 4 builtin, and nothing had ever run this script on
# macOS: the identical call in `check_pr_commit_messages.sh` exited 127 on the macOS lane with a
# message naming nothing about executable bits (D-208). `tests/test_lanes.py` now runs this as a
# subprocess and sweeps every script here for bash 4 spellings.
set -euo pipefail

ALLOWED=()

# `git ls-files --stage -z` prints `<mode> <object> <stage><TAB><path>`, NUL-terminated, and the
# entry is split in the shell. The earlier `awk '{ print $4 }'` split on whitespace, so a path
# with a space in it was reported truncated.
tab=$'\t'
executables=()
while IFS= read -r -d '' entry; do
  if [[ "${entry%% *}" == "100755" ]]; then
    executables+=("${entry#*"$tab"}")
  fi
done < <(git ls-files --stage -z)

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
