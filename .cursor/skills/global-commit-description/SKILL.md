---
name: global-commit-description
description: Drafts the next git commit message after inspecting the working tree and recent history, and always appends the tag [created_with_cursor]. Use when the user asks for a commit description, commit message, or next commit text and wants the Cursor-created marker included.
disable-model-invocation: true
---

# Commit description (with Cursor tag)

## Instructions

1. **Gather state** (run in repo root, in parallel when possible):
   - `git status` — staged/unstaged/untracked
   - `git diff` and `git diff --cached` — what will be committed
   - `git log -10 --oneline` — infer local commit message style (do not hard-code a style from another repo)

2. **Draft the message** following conventions from recent commits in **this** repository (prefixes, scope, imperative mood, body vs subject). If there is no clear pattern, use a short imperative subject and an optional body explaining *why*.

3. **Include the tag** `[created_with_cursor]` **verbatim** in every suggested commit message:
   - Prefer a **final line** in the body (after a blank line following the subject), e.g.  
     `Subject line`  
     *(blank line)*  
     `Body explaining why.`  
     `[created_with_cursor]`
   - If the user or project convention forbids a body line, put `[created_with_cursor]` at the **end of the subject line** separated by a space, still verbatim.

4. **Do not** run `git commit` unless the user explicitly asked to commit; this skill is for **generating the description** only.

5. If there are no changes to describe, say so and do not fabricate a message.

## Output format

Return the full proposed message in a single fenced block so the user can copy it, for example:

```text
Short imperative summary of the change

Explain the motivation or risk addressed in plain language.

[created_with_cursor]
```

## Examples (shape only; adapt to this repo's log)

**With body:**

```text
Align CI quality gate docs with ruff and bundle validate steps

Developers had no local make check target; document the three CI steps explicitly.

[created_with_cursor]
```

**Subject-only:**

```text
chore: bump example env defaults [created_with_cursor]
```
