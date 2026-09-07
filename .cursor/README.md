# Cursor rules and skills

AI guidance for this repository lives under **`.cursor/rules/`** (behavior) and **`.cursor/skills/`** (workflows). This tree is specific to **pcaptoparquet**, the open-source PCAP-to-parquet converter.

## Naming: `global-` vs `repo-`

| Prefix | Meaning |
|--------|---------|
| **`global-`** | Reusable on any similar stack (Python from `pyproject.toml`, Polars, post-change checks). |
| **`repo-`** | Specific to this repository: Makefile targets, `tests/` layout, protocol decoder modules. |

## Rules vs skills

- **Rules** (`.mdc`) — conventions the agent should follow. Some are `alwaysApply: true`; others attach via `globs`.
- **Skills** (`*/SKILL.md`) — step-by-step workflows (which tests to run, how tests are laid out, how to add a protocol decoder).

## Index

### Rules

| File | Scope |
|------|-------|
| `global-post-change-compliance.mdc` | Run quality gate + tests after non-trivial changes |
| `global-python-from-pyproject.mdc` | Read and conform to `pyproject.toml` |
| `global-polars-development.mdc` | Polars for tabular parquet export code |
| `repo-dev-workflow.mdc` | Makefile, `venv_build`, `make check` / `make test` |
| `repo-python-stack.mdc` | This repo's pyproject snapshot |

### Skills

| Folder | Scope |
|--------|-------|
| `global-commit-description/` | Draft a commit message from the working tree; append `[created_with_cursor]` |
| `global-devil-advocate/` | Stress-test a plan/design, then rewrite it into a corrected plan |
| `repo-fast-test-selection/` | Which pytest files to run for a given change |
| `repo-test-folder-structure/` | `tests/data`, `tests/config`, `tests/callbacks`, `tests/out` |
| `repo-protocol-decoder/` | Built-in and extension protocol `decode` modules |

Keep **README.md** and the **Makefile** aligned with `repo-dev-workflow` when adding official checks or test targets.
