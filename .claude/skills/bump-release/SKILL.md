---
name: bump-release
description: Bump the scpz version, update CHANGELOG, commit, push, and publish a GitHub release (which triggers PyPI publish). Use when the user says "bump", "release", "cut a release", or gives a version number like "v0.2.7".
license: MIT
---

# Bump Release

Releases are published to PyPI automatically when a GitHub release is created (`.github/workflows/publish.yml` triggers on `release: published`). The steps are: update version → update CHANGELOG → commit → push → `gh release create`.

## Step 1 — Determine the new version

If the user specified a version (e.g. `v0.2.7`), use it. Otherwise read the current version from `pyproject.toml` and increment:

- Patch (bug fixes, refactors, docs): `0.2.5` → `0.2.6`
- Minor (new features, backwards-compatible): `0.2.5` → `0.3.0`
- Major (breaking changes): `0.2.5` → `1.0.0`

Strip any leading `v` when writing to files; use `v`-prefixed form for git tags and `gh release create`.

## Step 2 — Identify what changed

```bash
git log $(git describe --tags --abbrev=0 origin/main 2>/dev/null || git rev-list --max-parents=0 HEAD)..HEAD --oneline
```

Read the commit messages to determine the CHANGELOG entries. Group by Added / Changed / Fixed / Removed.

## Step 3 — Update `pyproject.toml`

Edit the `version = "X.Y.Z"` line under `[project]`.

## Step 4 — Update `CHANGELOG.md`

The file uses [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) format.

1. Add a new `## [X.Y.Z] - YYYY-MM-DD` section immediately after `## [Unreleased]`, using today's date.
2. Leave `## [Unreleased]` empty above it.
3. Update the reference links at the bottom of the file:
   - Change `[Unreleased]:` to compare from the new tag: `https://github.com/tsjnsn/scpz/compare/vX.Y.Z...HEAD`
   - Add `[X.Y.Z]: https://github.com/tsjnsn/scpz/compare/vPREV...vX.Y.Z`

## Step 5 — Commit and push

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "chore: bump v{NEW_VERSION}"
git push origin main
```

## Step 6 — Create the GitHub release

Extract the new version's CHANGELOG section (everything between `## [X.Y.Z]` and the next `## [`) and use it as the release body.

```bash
gh release create vX.Y.Z \
  --title "vX.Y.Z" \
  --notes "$(CHANGELOG_BODY)"
```

This creates the tag on GitHub and publishes the release, which triggers the PyPI workflow automatically.

## Step 7 — Confirm

```bash
gh release view vX.Y.Z
```

Report the release URL to the user.

## Notes

- Do not run `uv build` or `twine upload` manually — PyPI publish is fully automated via GitHub Actions on release.
- The tag is created by `gh release create`; no need to run `git tag` separately.
- If `gh` is not authenticated, prompt: `gh auth login`.
