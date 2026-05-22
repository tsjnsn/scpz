# GitHub Pages setup (maintainers)

The repository includes a **Deploy documentation** workflow that builds this site with MkDocs and publishes it with the official Pages actions.

## One-time repository settings

1. In GitHub: **Settings** → **Pages** → **Build and deployment**.
2. Under **Source**, choose **GitHub Actions** (not “Deploy from a branch”).
3. Save if prompted.

The workflow (`.github/workflows/pages.yml`) runs on pushes to `main` or `dev-ai` when documentation-related paths change, and on **workflow_dispatch** for manual runs.

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
