# Claude Code skill

scpz ships a repository-root [`SKILL.md`](https://github.com/tsjnsn/scpz/blob/main/SKILL.md) so tools like Claude Code can discover when to suggest the CLI. The machine-readable front matter is omitted below; the body matches the file in git.

!!! note "Source of truth"
    Edit [`SKILL.md`](https://github.com/tsjnsn/scpz/blob/main/SKILL.md) for assistant-facing wording. This page embeds lines after the YAML front matter.

--8<-- "SKILL.md:15:158"

## Other automation

- [Bump / release skill](https://github.com/tsjnsn/scpz/blob/main/.claude/skills/bump-release/SKILL.md) — version bump, changelog, GitHub release, and PyPI via CI.
