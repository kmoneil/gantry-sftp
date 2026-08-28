#!/usr/bin/env bash
# Refuse a pull request whose commits carry a Claude Code session link.
#
# The belt to `forbid-session-trailer`'s braces. That hook runs only where somebody ran
# `pre-commit install`, and `git commit --no-verify` walks past it, so the local gate protects
# the machines that opted in. This reads the messages GitHub actually received, which is the
# only copy that matters once a branch is pushed.
#
# It asks the API rather than running `git log`, and that is the reason no checkout in `ci.yml`
# needs `fetch-depth: 0`: the default depth-1 clone has no history to walk, and deepening every
# job to gain one grep would be the expensive way to answer this.
#
# One message per API call rather than one call for all of them. A commit message is multi-line
# by convention here, so a single `--jq '.[].commit.message'` cannot be iterated line by line
# without splitting messages at their own newlines.
#
# Delegates the actual decision to `forbid_session_trailer.sh` so the pattern, the anchoring and
# the exclusions have one definition. A second copy of the regex in YAML is a second thing to
# update and the one nobody would.
set -euo pipefail

repository="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is unset}"
pull_request="${PR_NUMBER:?PR_NUMBER is unset}"
workdir="${RUNNER_TEMP:-/tmp}"
guard="$(dirname "$0")/forbid_session_trailer.sh"

mapfile -t shas < <(
  gh api --paginate "repos/${repository}/pulls/${pull_request}/commits" --jq '.[].sha'
)

# The third state of the predicate. A wrong number, a renamed field or an API that answered with
# an empty list all reach here, and every one of them would otherwise report the same green as a
# pull request whose messages were read and found clean.
if ((${#shas[@]} == 0)); then
  echo "error: pull request #${pull_request} reported no commits, so nothing was examined" >&2
  exit 1
fi

status=0
for sha in "${shas[@]}"; do
  gh api "repos/${repository}/commits/${sha}" --jq '.commit.message' > "${workdir}/commit-message"
  if ! bash "$guard" "${workdir}/commit-message"; then
    echo "  in commit ${sha}" >&2
    status=1
  fi
done

echo "checked ${#shas[@]} commit message(s) on pull request #${pull_request}"
exit "$status"
