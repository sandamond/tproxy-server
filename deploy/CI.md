# Continuous deployment

`master` is built and deployed by two GitHub Actions workflows,
[`.github/workflows/test.yml`](../.github/workflows/test.yml) and
[`.github/workflows/deploy.yml`](../.github/workflows/deploy.yml). This
document is the trust model behind them: why a self-hosted runner sitting on
the production host is safe to use on a public repository, what it can and
cannot do, and how to operate it.

## The problem a self-hosted runner normally creates

GitHub's own documentation warns against using self-hosted runners with
public repositories: anyone can fork a public repo and open a pull request,
and if a workflow that pull request can influence executes on a self-hosted
runner, that PR gets arbitrary code execution on whatever host the runner
lives on. On this repository, that host is the production relay serving real
client keys - that would be a real compromise, not a hypothetical one.

## Why this deployment doesn't have that problem

The two workflows are split by trust level, not just by task:

- **`test.yml`** runs on GitHub-hosted runners (`ubuntu-latest`) for both
  `pull_request` (any branch, forks included) and `push` to `master`. Hosted
  runners are ephemeral, sandboxed, and have no access to this host or its
  secrets, so it's safe to run for anyone's PR.
- **`deploy.yml`** runs on the self-hosted runner (label `tproxy-deploy`) and
  triggers **only** on `push` to `master` - never on `pull_request`, not even
  for this repository's own PRs.

A `push` event on `master` can only exist as the result of a merge, and
`master` is a GitHub branch-protection-protected branch: direct pushes are
refused (`enforce_admins` is on, so this applies to the repository owner
too), and merging requires being a repository collaborator. A fork can
change `deploy.yml` or add a malicious step in its own copy of the file, but
nothing a fork does can make GitHub emit a `push` event against *this*
repository's `master` - only an actual merge, performed by someone with
write access, does that. That is the entire safety property the self-hosted
runner rests on; it does not depend on GitHub's separate "require approval
for outside collaborators" setting for workflow runs, though that setting is
also enabled here as defense in depth for `test.yml`.

Practical consequence: reviewing what's allowed to reach the runner reduces
to reviewing who can merge to `master` (currently: the repository owner
alone) and what `deploy.yml` and `ci-deploy.sh` actually execute (below) -
not to auditing every past or future community PR.

## What actually runs on the runner, and as whom

The self-hosted runner's systemd service (`actions-runner-tproxy-server`)
runs as an unprivileged, dedicated Linux user (`ghrunner`), not root. Its
only path to privilege is one exact, argument-free sudoers rule:

```
ghrunner ALL=(root) NOPASSWD: /usr/local/sbin/ci-deploy.sh
```

`ci-deploy.sh` ([`deploy/ci-deploy.sh`](ci-deploy.sh)) takes no arguments and
reads nothing attacker-influenced beyond the already-merged repository
checkout at a fixed path; it calls
[`deploy/update-relay.sh`](update-relay.sh) and
[`keys-panel/deploy/update-keys-panel.sh`](../keys-panel/deploy/update-keys-panel.sh),
the same test-build-validate-install-with-rollback scripts described in the
main [`README.md`](../README.md#operations-and-updates) and
[`keys-panel/README.md`](../keys-panel/README.md). It does not touch
`profiles.json`, systemd units, Caddy, MTProxy's config, or the public site,
matching those scripts' own documented scope.

**`ci-deploy.sh` and its sudoers grant are not redeployed by the pipeline
they gate.** Installing `/usr/local/sbin/ci-deploy.sh` and the sudoers file
is a manual, one-time (or manually repeated) step on the runner host,
described below - never something `deploy.yml` writes to. If the pipeline
could rewrite the privileges it runs under, a single bad or malicious merge
could escalate itself on its very next run; keeping that file and its grant
outside the automated path is what prevents that.

## Runner installation (reference / disaster recovery)

Already done once on the production host; this is what to repeat if the
runner needs reinstalling.

```bash
sudo useradd --system --create-home --home /home/ghrunner --shell /usr/sbin/nologin ghrunner
sudo install -d -o ghrunner -g ghrunner -m 0755 /home/ghrunner/actions-runner
cd /home/ghrunner/actions-runner
sudo -u ghrunner curl --fail --silent --show-error --location \
  --proto '=https' --proto-redir '=https' --tlsv1.2 \
  -o actions-runner-linux-x64.tar.gz \
  https://github.com/actions/runner/releases/download/v2.337.0/actions-runner-linux-x64-2.337.0.tar.gz
test "$(sha256sum actions-runner-linux-x64.tar.gz | awk '{print $1}')" = "70920811a4f8ad4328818682bca5c6469c1c942fab52448868071d0063816613"
sudo -u ghrunner tar xzf actions-runner-linux-x64.tar.gz

# Registration tokens are single-use and expire in about an hour; generate
# one right before configuring the runner, from a machine with gh authorized
# against this repository (not necessarily this host):
#   gh api -X POST repos/sandamond/tproxy-server/actions/runners/registration-token --jq .token

sudo -u ghrunner ./config.sh --url https://github.com/sandamond/tproxy-server \
  --token "$REGISTRATION_TOKEN" \
  --name dev-landing-prod --labels tproxy-deploy --work _work --unattended --replace
sudo ./svc.sh install ghrunner
sudo ./svc.sh start
```

Install the deploy wrapper and its narrow sudo grant (also manual, see above
for why):

```bash
sudo install -o root -g root -m 0700 deploy/ci-deploy.sh /usr/local/sbin/ci-deploy.sh
echo 'ghrunner ALL=(root) NOPASSWD: /usr/local/sbin/ci-deploy.sh' | sudo tee /etc/sudoers.d/tproxy-ci-runner >/dev/null
sudo chmod 0440 /etc/sudoers.d/tproxy-ci-runner
sudo visudo -c
```

`ci-deploy.sh` changes: edit the file in the repository, get it merged like
anything else, then manually re-run the `install` line above on the runner
host. `deploy.yml` will keep calling the old version until that's done - by
design, per the section above.

## Required repository settings

- Branch protection on `master`: PR required, `enforce_admins` on, force-push
  and deletion disallowed, `required_conversation_resolution` on. Once
  `test.yml` had run for real, its three job names became required status
  checks with `strict: true` (branch must be up to date with `master` to
  merge):

  ```bash
  gh api --method PUT repos/sandamond/tproxy-server/branches/master/protection \
    --input - <<'JSON'
  {"required_status_checks":{"strict":true,"contexts":["relay","keys-panel","shellcheck-syntax"]}, ...}
  JSON
  ```

  (the full body needs every other protection field repeated - this endpoint
  replaces the whole configuration, it doesn't merge a partial update.)
  `deploy` is deliberately **not** in that list: it only ever runs after a
  push to `master`, so requiring it on a PR would be a check that can never
  pass before the merge that's supposed to produce it.
- "Fork pull request workflows from outside collaborators" set to require
  approval for all external contributors (already applied):

  ```bash
  gh api --method PUT repos/sandamond/tproxy-server/actions/permissions/fork-pr-contributor-approval \
    -f approval_policy=all_external_contributors
  ```

  Defense in depth for `test.yml` on the hosted runner; not load-bearing for
  the self-hosted runner's safety, which rests on the trigger topology above.
  This setting has three possible values
  (`first_time_contributors_new_to_github`, `first_time_contributors`,
  `all_external_contributors`) - GitHub's own naming, not something to guess
  from the web UI label alone.

## Automated review bots and `required_conversation_resolution`

This repository has the Codex GitHub App (`chatgpt-codex-connector`) reviewing
pull requests. `required_conversation_resolution` blocks merging while any
review thread is unresolved, bot-authored ones included - the first CI PR
here got stuck on exactly this until an unresolved Codex comment was
addressed and its thread resolved. If a PR won't merge and every status
check is green, check for an open review thread before assuming something
else is wrong.

## If the pipeline is down

`deploy/update-relay.sh` and `keys-panel/deploy/update-keys-panel.sh` are
ordinary scripts; run them by hand over SSH exactly as before this pipeline
existed if the runner or GitHub Actions itself is unavailable. Nothing about
normal operation depends on the pipeline being up.
