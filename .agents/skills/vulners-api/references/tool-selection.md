# Tool selection guidance

Use this reference to choose the right workflow when working on the Vulners API SDK.

## Editing SDK code

Use this skill when modifying files under:

```text
src/vulners/**/*.py
```

Expected checks (the project uses `uv`, not Poetry):

```bash
uv run ruff check src samples
uv run ruff format --check src samples
uv run mypy
uv run basedpyright
```

`make format`, `make lint`, `make typecheck`, and `make test` are the repository
shortcuts; `make check` runs lint + typecheck + unasync-check + test. When editing an
async resource under `src/vulners/_resources/_async/`, regenerate the committed sync
mirror with `make unasync` (gated by `make unasync-check`).

## Editing examples

Use this skill when modifying files under:

```text
samples/**/*.py
```

Requirements:

- Use `VULNERS_API_KEY` from the environment.
- Keep examples defensive.
- Keep examples short enough for users to copy and adapt.
- Clearly state whether the example makes live network calls.

## Editing docs

Use this skill when modifying:

```text
README.md
documentation/**/*.md
CONTRIBUTING.md
SECURITY.md
```

Requirements:

- Avoid real secrets and real private infrastructure data.
- Keep API examples current with the SDK interface.
- Include enough context for new contributors.

## Adding CI or automation

Use repository automation paths only when creating the missing automation structure:

```text
.github/workflows/*.yml
.github/dependabot.yml
```

Recommendations:

- Run lint, format check, type check, and tests.
- Use a Python version matrix.
- Keep publishing workflows separate from pull request CI.
- Use least-privilege GitHub Actions permissions.

## Adding new skills

New skills should live under:

```text
.agents/skills/<skill-name>/SKILL.md
```

Optional supporting files:

```text
.agents/skills/<skill-name>/references/
.agents/skills/<skill-name>/scripts/
.agents/skills/<skill-name>/assets/
```
