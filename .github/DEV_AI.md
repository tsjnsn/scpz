# `dev-ai` branch and Copilot coding agent

`dev-ai` is the integration branch for agent-assisted work (Copilot coding agent, Cursor,
Dependabot catalog PRs). The release PR **`dev-ai` → `main`** is where strict CI and review
gates belong—not on every direct push to `dev-ai`.

## Why Copilot could not push (GH006)

If a Copilot session fails with:

```text
GH006: Protected branch update failed for refs/heads/dev-ai
remote: - 3 of 3 required status checks are expected.
```

Copilot finished the fix locally but **could not push** to `dev-ai`. Classic branch
protection (or a ruleset) was requiring status checks on the **new commit before the push
lands**. CI has not run on that commit yet, so GitHub rejects the push.

That is unrelated to test failures; regular CI on the PR head may already be green.

## Recommended setup

| Branch | Role | Protection |
|--------|------|------------|
| `dev-ai` | Integration; agents push review fixes here | Light ruleset; **no** required status checks on push |
| `main` | Production | Strict rules + required CI on merge (PR / merge queue) |

### 1. Replace classic `dev-ai` protection with the integration ruleset

**Repository admin** (one-time):

1. **Settings → Branches** — if there is a classic protection rule for `dev-ai`, **delete it**.
   (Leaving it in place will keep blocking Copilot even after you import the ruleset.)

2. **Settings → Rules → Rulesets → New ruleset → Import a ruleset**

   Import [`.github/rulesets/dev-ai-copilot-integration.json`](rulesets/dev-ai-copilot-integration.json).

   That ruleset:

   - Applies only to `refs/heads/dev-ai`
   - Blocks branch deletion and force-push for **everyone** (including Copilot)
   - Does **not** require status checks before push, so the coding agent can land commits
     without GH006 from “checks expected before the push”

3. Or apply via CLI (admin token):

   ```bash
   ./scripts/apply_dev_ai_ruleset.sh
   ```

### 2. Keep strict CI on `dev-ai` → `main`

On the **pull request** (or on `main` / merge queue), require the CI jobs from
[`.github/workflows/ci.yml`](workflows/ci.yml), for example:

- Lint & Format
- Type Check
- Test (Python 3.13)

Add **Equivalence golden regression** when that job is required for merges.

Copilot can push to `dev-ai` without those checks having already run on its new commit
because `dev-ai` itself does not require them before push; the PR into `main` still must go
green before merge.

### 3. Enable Copilot coding agent on this repository

**Settings → Copilot → Coding agent** (or org policy): enable the agent for `tsjnsn/scpz`.

On the pull request, comment e.g. `@copilot please address the review comments` so it works on the PR
head branch (`dev-ai`).

## What not to do

- Do **not** require the same status checks on direct pushes to `dev-ai` if you want Copilot
  to land fixes on the open PR without a second PR.
- Do **not** expect a separate `copilot/*` PR unless you intentionally want that flow; for
  `dev-ai` → `main`, configure a light ruleset on `dev-ai` instead (for example this repo’s
  importable ruleset).

## References

- [About rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [About GitHub Copilot coding agent](https://docs.github.com/en/copilot/concepts/agents/coding-agent/about-coding-agent)
