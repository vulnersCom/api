# Tool selection guidance

Use this reference to choose the right workflow when working on the Vulners API SDK.

## Editing SDK code

Use this skill when modifying files under:

```text
vulners/**/*.py
```

Expected checks:

```bash
poetry run ruff check vulners samples
poetry run ruff format --check vulners samples
poetry run mypy vulners
```

`make format`, `make isort`, `make mypy`, and `make cc` are available repository shortcuts.
Use `poetry run pytest` only after adding `pytest` to the dev dependencies and creating tests.

The root `scripts/format` helper uses the declared ruff tooling. Prefer the Makefile and
ruff-based scripts unless a task explicitly updates the development dependency set.

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
docs/**/*.md
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
