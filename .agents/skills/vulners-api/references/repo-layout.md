# Repository storage locations

Use this reference when deciding where a new file belongs.

## Current locations

```text
.agents/skills/                         Agent skills and reusable AI workflow knowledge
.agents/skills/vulners-api/SKILL.md     Main skill file for Vulners API SDK work
.agents/skills/vulners-api/references/  Supporting skill documentation
.agents/skills/vulners-api/scripts/     Helper scripts used by the skill, not project automation
samples/                                Example scripts for SDK users
scripts/                                Project maintainer or utility scripts
vulners/                                Runtime Python SDK package
vulners/vulners/                        Main VulnersApi domain modules
vulners/vscanner.py                     VScannerApi facade
README.md                               User-facing project introduction
AUTHORS                                 Project authors
LICENSE                                 Project license
Makefile                                Current ruff/mypy helper targets
pyproject.toml                          Python package metadata and tooling
```

## Target create-if-needed locations

These paths are useful targets when the work requires them, but they are not present by default:

```text
.github/workflows/                      GitHub Actions workflows
.github/ISSUE_TEMPLATE/                 Issue templates
.github/pull_request_template.md        Pull request template
docs/                                   Human-facing documentation
tests/                                  Unit and integration tests
CONTRIBUTING.md                         Contribution process
SECURITY.md                             Vulnerability disclosure policy
```

Do not reference Copilot/Cursor/Claude harness files unless you are explicitly adding support for
that harness. This skill's active location is `.agents/skills/vulners-api/SKILL.md`.

## Rule of thumb

- Runtime code goes in `vulners/`.
- User examples go in `samples/`.
- Project maintainer automation goes in root `scripts/`.
- Skill-only automation goes in `.agents/skills/vulners-api/scripts/`.
- Test code goes in `tests/`.
- CI and repository automation go in `.github/`.
- Agent-only reusable instructions go in `.agents/skills/`.
- Secrets do not go anywhere in the repository.
