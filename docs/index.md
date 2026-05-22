# scpz documentation

**scpz** is a correctness-minded Python CLI that optimizes AWS Service Control Policy (SCP) JSON so it fits AWS Organizations limits: **10,240 bytes** per policy, **5 statements** per SCP, and up to **10 SCPs** per account or OU.

## Explore

| Section | What you will find |
| --- | --- |
| [User guide](user-guide.md) | Install, commands, optimization passes, and configuration (from the project README). |
| [Claude skill](claude-skill.md) | How AI assistants discover scpz via `SKILL.md`, plus links to automation skills. |
| [Agent rules](agents.md) | Contributor and automation expectations (`AGENTS.md`). |
| [Contributing](contributing.md) | Local setup, checks, and pull request expectations. |
| [Changelog](changelog.md) | Release history. |

Use the **search bar** in the header to jump to any heading or phrase across these pages.

## Quick links

- [Repository](https://github.com/tsjnsn/scpz)
- [Issues](https://github.com/tsjnsn/scpz/issues)
- [PyPI package](https://pypi.org/project/scpz/)
- [CI status](https://github.com/tsjnsn/scpz/actions/workflows/ci.yml)

## Maintainer note

If the site does not update after a merge, confirm [GitHub Pages is set to deploy from Actions](pages-setup.md).
