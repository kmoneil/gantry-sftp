#!/usr/bin/env bash
# Warn -- never fail -- when a session has left a worktree parked under `.claude/worktrees/`.
#
# The failure this guards against is not knowing. A background session that finishes a turn
# reports `done`, which is the same state it reports while it sits idle waiting for an answer:
# nothing distinguishes "waiting for you" from "over". Its worktree stays behind and stays
# `locked`, because the keep-or-remove prompt belongs to the interactive exit path and a
# daemon-backed job never runs it. Nothing in the repository surfaces that. `git status` in the
# main checkout is clean whatever is parked next door, no other hook looks outside the checkout
# it was invoked in, and the session's transcript is filed under a project key derived from the
# *worktree* path, so it does not appear beside this project's own sessions either. One was
# found on 2026-08-04 holding a duplicate of work that had already landed on `main` from a
# different session, a day after it was abandoned -- it read as a discovery rather than as an
# echo, and the question it cost was whether the mutation lane had been finished at all.
#
# It warns rather than gates on purpose, and that is the whole design. Working in a worktree is
# the supported thing to do, so a hook that blocked the commit would be wrong every time
# somebody legitimately has two going, and a gate that is wrong on the normal case is a gate
# people learn to skip. This one is only ever noise-free or informative.
#
# `verbose: true` on the hook in `.pre-commit-config.yaml` is load-bearing: pre-commit hides the
# stdout of a *passing* hook, and this hook always passes, so without it every word below goes
# into a void and the hook looks installed while telling nobody anything. The quiet case is
# genuinely quiet -- nothing is printed when nothing is parked -- so it costs the one status
# line pre-commit prints for each hook regardless.
set -euo pipefail

here=$(git rev-parse --show-toplevel)

parked_paths=()
parked_labels=()

path=""
branch=""
head=""
locked=""

flush() {
  # A worktree is "parked" if it lives under `.claude/worktrees/` and is not the one this
  # commit is being made from. Committing from inside a parked worktree is normal -- that is
  # what it is for -- and reporting it to itself would be the noise that gets the hook removed.
  if [[ -z "$path" || "$path" == "$here" || "$path" != */.claude/worktrees/* ]]; then
    return 0
  fi

  # The tip is read from *this* repository rather than with `git -C "$path"`: worktrees share
  # one object store, and a registration whose directory has been deleted is exactly the case
  # worth reporting, so it must not be the case that errors.
  local when="date unknown"
  if [[ -n "$head" ]]; then
    when=$(git log -1 --format=%cr "$head" 2>/dev/null || echo "date unknown")
  fi

  local label="  ${path#"$here"/}  [${branch:-detached}]  last commit ${when}"
  if [[ -n "$locked" ]]; then
    label+="  (locked)"
  fi
  if [[ ! -d "$path" ]]; then
    label+="  (directory is gone -- registration only)"
  fi

  parked_paths+=("$path")
  parked_labels+=("$label")
}

while IFS= read -r line; do
  case "$line" in
    "worktree "*)
      flush
      path=${line#worktree }
      branch=""
      head=""
      locked=""
      ;;
    "HEAD "*) head=${line#HEAD } ;;
    "branch "*) branch=${line#branch refs/heads/} ;;
    "locked"*) locked="yes" ;;
  esac
done < <(git worktree list --porcelain)
flush

if ((${#parked_paths[@]} == 0)); then
  exit 0
fi

echo "note: ${#parked_paths[@]} parked worktree(s) under .claude/worktrees/ -- a session may be waiting there:"
printf '%s\n' "${parked_labels[@]}"
echo
echo "Check it before duplicating its work; its session is in /tasks."
echo "Remove one with:  git worktree unlock <path> && git worktree remove --force <path>"
echo "                  git branch -D <branch>"

exit 0
