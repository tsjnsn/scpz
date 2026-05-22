# scpz

**scpz** is a correctness-minded Python CLI that optimizes AWS Service Control Policy (SCP) JSON to fit AWS Organizations limits: **10,240 bytes** per policy, **5 statements** per SCP, and up to **10 SCPs** per account or OU.

## Documentation

| Page | Contents |
|:-----|:---------|
| [User guide](user-guide.md) | Install, CLI usage, optimization passes, configuration |
| [Claude skill](claude-skill.md) | Assistant skill (`SKILL.md`) and related automation |
| [Agent rules](agents.md) | Expectations for contributors and coding agents |
| [Contributing](contributing.md) | Local setup, checks, pull requests |
| [Changelog](changelog.md) | Release notes |
| [GitHub Pages setup](pages-setup.md) | One-time Pages enablement for maintainers |

Use **Search** in the header to jump to any heading.

## Links

- [Repository](https://github.com/tsjnsn/scpz)
- [Issues](https://github.com/tsjnsn/scpz/issues)
- [PyPI](https://pypi.org/project/scpz/)
- [CI](https://github.com/tsjnsn/scpz/actions/workflows/ci.yml)

## Maintainer note

If the site does not update after a merge, confirm [GitHub Pages is set to deploy from Actions](pages-setup.md).
