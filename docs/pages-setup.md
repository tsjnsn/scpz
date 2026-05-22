# GitHub Pages setup (maintainers)

The repository includes a **Deploy documentation** workflow that builds this site with MkDocs and publishes it with the official Pages actions.

## One-time repository settings (required)

Until this is done, **no Pages site exists** for the repository. The REST endpoint `GET /repos/{owner}/{repo}/pages` returns **404**, and the deploy step fails with errors such as **Failed to create deployment (status: 404)** because `actions/deploy-pages` has nothing to publish to.

1. Open **Settings** → **Pages** for the repository:  
   [github.com/tsjnsn/scpz/settings/pages](https://github.com/tsjnsn/scpz/settings/pages)
2. Under **Build and deployment** → **Source**, choose **GitHub Actions** (not “Deploy from a branch”).
3. Save if prompted.

Also ensure **Actions** are allowed: **Settings** → **Actions** → **General** → *Actions permissions* should allow workflows to run (org policy can block this).

The workflow (`.github/workflows/pages.yml`) runs on pushes to `main` when documentation-related paths change, and on **workflow_dispatch** (use the `main` branch). Documentation builds on `dev-ai` are validated by the CI **Documentation site** job; only `main` deploys to the `github-pages` environment.

## After enabling Pages

1. In **Actions**, open **Deploy documentation** and **Re-run all jobs** on the latest failed run, or use **Run workflow** on `main`.
2. Wait for the **Deploy to GitHub Pages** job to finish.
3. Confirm the site responds (HTTP 200):  
   [https://tsjnsn.github.io/scpz/](https://tsjnsn.github.io/scpz/)

## Verification (maintainers)

With the [GitHub CLI](https://cli.github.com/) authenticated as a user who can manage Pages:

```bash
gh api repos/tsjnsn/scpz/pages --jq '{status, build_type, html_url}'
```

- **Before enablement:** the API returns **404 Not Found**.
- **After enablement:** you should see `build_type` set to **`workflow`** and an `html_url` for the site.

## Optional: enable via API

Repository **administrators** (or roles with “manage GitHub Pages settings”) can create the Pages configuration without using the web UI:

```bash
gh api --method POST repos/tsjnsn/scpz/pages \
  --input - <<'EOF'
{"build_type": "workflow"}
EOF
```

Use a token with `repo` scope (classic) or equivalent fine-grained permissions for repository administration and Pages.

## Expected URL

Project Pages for `tsjnsn/scpz` are served at:

[https://tsjnsn.github.io/scpz/](https://tsjnsn.github.io/scpz/)

If the URL differs (fork, rename), update `site_url` in `mkdocs.yml` and any badges or links that point at the old location.

## Local preview

```bash
uv sync --group docs
uv run mkdocs serve
```

Open the printed local URL (usually `http://127.0.0.1:8000/`).
