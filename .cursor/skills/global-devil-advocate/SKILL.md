---
name: global-devil-advocate
description: >-
  Critically audit a plan, design, or proposal for gaps, inconsistencies, and
  risks, then rewrite it into a corrected, ready-to-execute plan. Covers code
  optimization, internal contradictions, naming conventions, architecture,
  performance, scalability/capacity, security, and operability. Use when the
  user asks to play devil's advocate, poke holes in and fix a plan, stress-test
  and correct a design, or harden a proposal/RFC/spec before implementation.
disable-model-invocation: true
---

# Devil's Advocate Plan Correction

Adopt an adversarial, skeptical stance to find what's wrong, missing, or
contradictory in a plan **before** it is built — then **fix it**. The
deliverable is a corrected plan, not a critique. Reviewing is only the means;
the output is an improved, ready-to-execute plan.

## Operating Principles

- **Fix, don't just flag.** For every gap or inconsistency you find, resolve it
  directly in the plan. Only leave an open question when the fix genuinely
  depends on information you don't have and can't reasonably assume.
- **Be concrete.** Tie every change to a specific step, assumption, or component.
- **Preserve intent.** Keep the plan's original goal and structure; change what's
  broken, not what already works. Don't rewrite for taste.
- **Make minimal, justified edits.** Prefer the smallest change that removes the
  flaw over a wholesale redesign — unless the approach itself is unsound, in
  which case replace it and say why.
- **Don't invent problems.** If a dimension is genuinely fine, leave it alone.

## Correction Dimensions

Audit the plan against each dimension. Wherever it falls short, rewrite the
affected part of the plan to remove the flaw. Skip dimensions that clearly don't
apply.

### 1. Contradictions & Consistency
- Do any two requirements, steps, or decisions conflict?
- Does the plan contradict stated goals, constraints, or prior decisions?
- Are terms/units/data models used consistently throughout?

### 2. Gaps & Missing Cases
- What's unspecified: error handling, edge cases, empty/nil/overflow, failure
  and rollback paths, migrations, backward compatibility?
- Missing steps, undefined ownership, or hand-waved "TODO later" pieces?
- Unstated assumptions that, if false, sink the plan?

### 3. Architecture & Design
- Right boundaries and coupling? Hidden circular or bidirectional dependencies?
- Single points of failure? Missing abstraction or over-engineering (YAGNI)?
- Does it fit existing patterns in the codebase, or fight them?

### 4. Code Optimization & Quality
- Redundant work, N+1 queries, unnecessary allocations, repeated computation?
- Simpler approach that achieves the same result with less code/risk?
- Testability: can this be tested in isolation? What's hard to test and why?

### 5. Naming & Conventions
- Names accurate, unambiguous, and consistent with existing conventions?
- Misleading names (says one thing, does another)? Leaky or inconsistent casing?

### 6. Performance & Capacity
- Bottlenecks under expected and peak load? Big-O of hot paths?
- Memory/CPU/IO/network budget? Behavior at 10x and 100x current scale?
- Caching/pagination/batching considered where needed?
- Resource limits, quotas, connection pools, rate limits, timeouts.

### 7. Security & Data
- Input validation, authn/authz, injection, secrets handling, PII exposure?
- Trust boundaries crossed without checks?

### 8. Operability & Observability
- How is failure detected? Logging, metrics, alerting, tracing?
- Deployability, config/feature-flag rollout, and safe rollback?

### 9. Correctness of Estimates & Reasoning
- Are effort/complexity/impact claims justified or hopeful?
- Does the cost/benefit actually hold up?

## Output Format

Lead with the corrected plan. The changelog is a short appendix for traceability.

```markdown
## Corrected Plan

<The full, revised plan — self-contained and ready to execute. Same structure as
the original where it was sound, with flaws fixed inline. This is the primary
deliverable; it must stand on its own without reading the original.>

## What Changed & Why

- **<fixed issue>** — <the flaw, and the correction applied to the plan>

## Open Questions (only if a fix truly can't be made without input)

- <the unknown, the assumption taken as default, and how the answer would change
  the plan>
```

Rules for the output:
- The corrected plan is the deliverable. Do not stop at listing problems.
- Fix every issue you can inline. Use "Open Questions" only when a decision is
  genuinely the user's to make — and still apply a sensible default in the plan
  so it remains executable.
- If the plan needed no changes, output it unchanged and say so in one line.
