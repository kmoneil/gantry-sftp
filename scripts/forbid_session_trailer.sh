#!/usr/bin/env bash
# Reject a commit message carrying a Claude Code session link.
#
# A commit message is permanent. Removing one of these from published history cost a rewrite of
# three commits on `main`, an unlocked branch ruleset and a force-push on 2026-08-28, and it
# still left the old objects reachable by SHA on a public repository. That is why this gates
# rather than warns: the cheap moment to refuse it is before the object exists.
#
# What stops it being written in the first place is `attribution.sessionUrl: false` in
# `~/.claude/settings.json`. That file is per-machine and outside this repository, so it
# protects the machine it is on and nothing else. This hook is the half that travels with the
# code, which is the same argument `forbid_exec_bit.sh` makes for checking the index.
#
# Invoked via `bash` rather than executed, like the exec-bit hook, so it does not need the bit
# it would otherwise have to allowlist itself for.
#
# Two patterns, and they are deliberately not the same shape. A line that *is* the trailer is
# what a tool emits, so it is anchored: a message may still discuss the trailer in prose, which
# this file's own commit had to do. A session URL is the payload that must never land, so it is
# refused anywhere in the message.
set -euo pipefail

message_file="${1:?usage: forbid_session_trailer.sh <commit-message-file>}"

if [[ ! -f "$message_file" ]]; then
  echo "error: no commit message file at '$message_file'" >&2
  exit 1
fi

# Everything from the scissors line down is the diff `git commit -v` appends, and comment lines
# are stripped by git before the message is stored. Scanning either would refuse a commit for
# text that never becomes part of it -- including, for this repository, a staged diff of this
# very script.
body="$(sed '/^#.*>8/,$d' "$message_file" | grep -v '^[[:space:]]*#' || true)"

violations=()
if grep -qiE '^[[:space:]]*Claude-Session:' <<<"$body"; then
  violations+=("a Claude-Session: trailer line")
fi
if grep -qiE 'claude\.ai/code/session' <<<"$body"; then
  violations+=("a claude.ai session URL")
fi

if ((${#violations[@]} > 0)); then
  echo "error: the commit message carries a Claude Code session link:" >&2
  printf '  %s\n' "${violations[@]}" >&2
  echo >&2
  echo "A commit message cannot be edited after it is pushed without rewriting history." >&2
  echo "Remove the line, then commit again." >&2
  echo >&2
  echo "To stop it being written at all, set this in ~/.claude/settings.json:" >&2
  echo '  "attribution": { "commit": "", "pr": "", "sessionUrl": false }' >&2
  exit 1
fi
