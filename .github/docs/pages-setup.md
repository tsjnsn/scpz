# GitHub Pages setup (maintainers)

The **Deploy documentation** workflow (`.github/workflows/pages.yml`) builds this site with MkDocs and publishes it via the official Pages actions.

## One-time repository settings

Until Pages is enabled, `GET /repos/{owner}/{repo}/pages` returns **404** and deploy fails with **Failed to create deployment (status: 404)**.

1. **Settings** → **Pages**: [github.com/tsjnsn/scpz/settings/pages](https://github.com/tsjnsn/scpz/settings/pages)
2. **Build and deployment** → **Source** → **GitHub Actions** (not “Deploy from a branch”).
3. Ensure **Settings** → **Actions** → **General** allows workflows (org policy can block this).

The workflow runs on pushes to `main` or `dev-ai` when documentation paths change, and on **workflow_dispatch**.

## After enabling Pages

1. In **Actions**, re-run **Deploy documentation** or trigger **Run workflow** on `dev-ai` / `main`.
2. Wait for **Deploy to GitHub Pages** to finish.
3. Confirm [https://tsjnsn.github.io/scpz/](https://tsjnsn.github.io/scpz/) returns HTTP 200.

## Verification

With [GitHub CLI](https://cli.github.com/) and repo admin access:

```bash
gh api repos/tsjnsn/scpz/pages --jq '{status, build_type, html_url}'
```

- **Before enablement:** 404.
- **After enablement:** `build_type` is **`workflow`** and `html_url` is set.

## Optional: enable via API

```bash
gh api --method POST repos/tsjnsn/scpz/pages \
  --input - <<'EOF'
{"build_type": "workflow"}
EOF
```

Requires `repo` scope (classic) or equivalent fine-grained Pages permissions.

## URL and config

Project Pages URL: [https://tsjnsn.github.io/scpz/](https://tsjnsn.github.io/scpz/)

For forks or renames, update `site_url` in `mkdocs.yml` and badges that reference the old URL.

## Local preview

```bash
uv sync --group docs
uv run mkdocs serve
```

Open the printed local URL (usually `http://127.0.0.1:8000/`).
