#!/usr/bin/env bash
set -euo pipefail

# Invoked as root via a single exact-match, no-argument sudoers rule from the
# unprivileged CI runner account (see deploy/CI.md). Nothing about this
# invocation is attacker-controllable through its arguments, because it takes
# none. The only externally-influenced input is the already fully tested
# repository checkout at the fixed path below, which only reaches this
# script by way of a `git push` to this repository's branch-protected
# `master` - i.e. only after a merge, which only a repository collaborator
# can perform. See deploy/CI.md for the full trust boundary this rests on.
#
# This script itself is NOT redeployed by the pipeline it drives: installing
# it and granting sudo access to it is a deliberate one-time (or manually
# repeated) step on the runner host, kept separate from the automatic update
# path below on purpose - see deploy/CI.md.

repository=/home/ghrunner/actions-runner/_work/tproxy-server/tproxy-server

if [[ "${EUID}" -ne 0 ]]; then
	echo "run as root (this script expects to be invoked through sudo)" >&2
	exit 1
fi
if [[ ! -d "$repository/.git" ]]; then
	echo "expected repository checkout not found at $repository" >&2
	exit 1
fi

echo "== relay =="
"$repository/deploy/update-relay.sh"

echo "== tproxy-keys =="
"$repository/keys-panel/deploy/update-keys-panel.sh"

echo "deploy complete"
