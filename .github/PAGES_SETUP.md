# GitHub Pages setup (maintainers)

Documentation deploys via **Deploy documentation** (`.github/workflows/pages.yml`), which builds with MkDocs and publishes with the official Pages actions.

## One-time settings

Until Pages uses **GitHub Actions** as the source, deploy fails with **404** (no Pages site exists yet).

1. **Settings → Pages** → [github.com/tsjnsn/scpz/settings/pages](https://github.com/tsjnsn/scpz/settings/pages)
2. **Build and deployment → Source:** **GitHub Actions** (not “Deploy from a branch”).
3. Confirm **Settings → Actions → General** allows workflows (org policy can block this).

The workflow runs on pushes to `main` or `dev-ai` when docs-related paths change, and on **workflow_dispatch**.

## After enabling

1. In **Actions**, re-run **Deploy documentation** or use **Run workflow**.
2. Confirm [https://tsjnsn.github.io/scpz/](https://tsjnsn.github.io/scpz/) returns HTTP 200.

```bash
gh api repos/tsjnsn/scpz/pages --jq '{status, build_type, html_url}'
```

Expect `build_type: workflow` after enablement; **404** before.

### Enable via API (admins)

```bash
gh api --method POST repos/tsjnsn/scpz/pages --input - <<'EOF'
{"build_type": "workflow"}
EOF
```

Requires a token with repository admin / Pages permissions.

## URL and config

Project Pages URL: [https://tsjnsn.github.io/scpz/](https://tsjnsn.github.io/scpz/). After a fork or rename, update `site_url` in `mkdocs.yml` and any badges.

## Local preview

```bash
uv sync --group docs
uv run mkdocs serve
```
