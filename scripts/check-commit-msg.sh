#!/usr/bin/env bash
# check-commit-msg.sh -- validates Conventional Commits 1.0 format.
#
# Invoked by lefthook's commit-msg hook with the path to the commit
# message file as $1. Exits non-zero with a helpful diagnostic if the
# subject line does not match the convention documented in DEVELOPMENT.md.
#
# Skipping a single commit: `git commit --no-verify`.

set -euo pipefail

msg_file="${1:?commit message file path required}"
subject="$(head -n1 "$msg_file")"

# Pass through git-internal commit subjects that follow their own format.
if [[ "$subject" =~ ^(Merge|Revert|fixup!|squash!|amend!) ]]; then
    exit 0
fi

# Conventional Commits 1.0 pattern:
#   <type>(<optional-scope>)?!?: <subject>
# Types match the allowlist in DEVELOPMENT.md; scope is kebab-case-ish.
pattern='^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(\([a-z0-9/_.,-]+\))?!?: .+'

if [[ ! "$subject" =~ $pattern ]]; then
    cat >&2 <<EOF
ERROR: Commit subject does not match Conventional Commits 1.0 format.

Got:
  $subject

Expected:
  <type>(<optional-scope>)?: <imperative subject, <=72 chars>

Allowed types:
  feat fix docs style refactor perf test build ci chore revert

Examples:
  feat(collectors/do): add Spaces public-ACL check
  fix(engine): bound goroutine fan-out by max_parallel
  docs: clarify evidence-pack redaction default

See DEVELOPMENT.md "Commit messages" for the full convention.
Skip this check with: git commit --no-verify
EOF
    exit 1
fi

# Length is a warning, not a hard error: it is sometimes worth a longer
# subject if breaking it would hurt readability. CI / review can flag.
if [[ ${#subject} -gt 72 ]]; then
    echo "WARNING: subject is ${#subject} chars; recommended <= 72." >&2
fi
