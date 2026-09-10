# Keep packet dumps off the prompt (token cost = result size)

Work only in **this** repository (`pcaptoparquet`). Follow `.cursor/rules` (Polars for tabular work, `make venv` / `make check` / `make test`). Do not add NBA, tcptrace, or p2p_testbench metrics as MCP tools. Do not convert PCAP inside MCP.

This prompt is the **next slice** after [mcp-general-query-engine.md](mcp-general-query-engine.md). That work shipped `list_captures` + `run(plan|preset)`. Keep that product. The remaining bug is that **packet-shaped `run()` results and retry loops** serialize far more than the answer into the model.

## Why this slice exists

An external Cursor-SDK harness asked the same connection-level question three ways on one bulk parquet (~1e6 packet rows, 22 source files concatenated, extra `filename` tag column):

| Arm | Uncached input tokens | Tool calls | Wall |
|---|---:|---:|---:|
| Parquet + Polars (shell, in-process) | ~38k | 17 | ~3 min |
| Parquet + this MCP (`run` only, shell off) | ~258k | 40 | ~18 min |

Accuracy matched. MCP lost because the agent **debugged in-band**: ~40 JSON envelopes (32 KiB cap, 30 s collect timeout, mean ~27.5 s/call). The Polars arm printed two filenames.

Two engine gaps made a one-shot plan impossible:

1. **No arithmetic** and **no join of two aggregates** (only `join_packets` back onto the packet scan).
2. **`ParquetCatalog.scan` drops extra columns** (`extra_columns="ignore"` then `select(PACKET_COLUMNS)`), so a concatenated bulk table **loses `filename`**. MCP cannot group by capture id on that file today.

A smaller lab query (distinct IPs after group-then-join on ≤1 MB) already fits in 5–7 `run()` calls with a **small aggregate** `data` table. Do not regress that. Capping **aggregates** to a 5-row preview would recreate the old failure mode (agent invents the rest of a 57-IP list). This slice must stop **packet dumps** and **rescan retries**, not shrink successful aggregate answers.

Acceptance test (unchanged):

> Token cost and latency should track **result size**, not **how many packets were scanned**.

## Goal

`run()` should match a Polars script for schema-valid questions: heavy work stays on the server; the tool result is an aggregate or a tiny packet preview. Still **not** a tool per study. Still **not** SQL.

## What is missing in the current code

`pcaptoparquet_mcp/queries.py` / `catalog.py` / `server.py` today:

- Ops: `filter`, `with_columns`, `select`, `unique`, `sort`, `group_by`, `join_packets`, `head`.
- Expressions: `col`, `lit`, `not`, `is_null`, `and`/`or`, `in`, `when`/`then`, comparisons. **No arithmetic. No datetime→ms.**
- Join: **only** `join_packets`. No aggregate ⋈ aggregate.
- Envelope: `_success_envelope` with full `data`, `MAX_RESULT_BYTES = 32768`. `_row_cap_for`: if `num` in columns → 200, else 5000. Empty plan on packets therefore returns **200 packet rows** (`test_packet_head_truncated`).
- Collect timeout 30 s → `{"error":"query timed out"}`. Worker thread is **not cancelled** (README already says this). No `explain` on timeout.
- `run` is **stateless**: every call `catalog.scan(capture)` from scratch.
- `scan()` **drops** CLI tag columns (`filename`, `path`, …).

`execute()` is the unit-testable core. Session state belongs in a small store used by `server.py`, not inside `catalog.py`.

## Target shape (decided APIs — do not offer three equivalents)

Keep tools: `list_captures`, `run`. **No** `collect` / `continue_frame` / `sql` tools. **No** Python parameter named `from` (keyword; invalid on `def run`).

```text
run(capture, plan=None, preset=None, args=None, explain=False, frame_id=None)
```

`frame_id` is optional: continue from a stored frame **of that same capture**.

### A. Envelope (breaking but same keys)

Success payload keys stay `columns`, `data`, `truncated`, `returned_rows` (plus `plan` if `explain`). Add:

- `frame_id` (string, success only — never on `error`)
- `n_rows`: integer total if known from **this** collect; **omit or null** if the collect was `head(cap+1)` truncated (do **not** run a second `count()` / full collect to learn the true total)

`data` is always the rows you are willing to send to the model. There is **no** separate `preview` key (two shapes would break hosts and `tests/test_mcp_server.py`).

**Row policy (this is the token fix):**

| Final schema | Default `data` | Cap |
|---|---|---|
| Packet-shaped (`num` in columns) | **5 rows** | `head(6)` to set `truncated`; never more than `PACKET_ROW_LIMIT` (200) even if `head` asks |
| Aggregate / distinct (`num` absent) | **Full agg** as today | `AGG_ROW_LIMIT` (5000) and 32 KiB |

Last-step `head` with `n` applies **before** those caps (`n` then packet-vs-agg cap). Agents that need more than 5 **packets** pass `head`. Agents that need a distinct IP list **must not** be preview-capped: that list is aggregate-shaped after `unique`/`group_by` without `num`.

Presets: **unchanged** (they already return small mix/SNI/sample tables). Do not wrap `summarize_capture` in a 5-row preview.

32 KiB remains the **hard ceiling** on the JSON envelope (`_success_envelope` already clips `data`). Do not raise `MAX_RESULT_BYTES`. If byte-clip fires on an aggregate, `truncated` is true; the agent’s next step is `sort`+`head` **on `frame_id`**, not a wider dump.

### B. Session store (server process, stdio lifetime)

Module (e.g. `pcaptoparquet_mcp/frames.py`) + wire-up in `server.py`:

Each successful `run` stores:

- `capture` (relative path string)
- `packets_lf`: **lazy** `catalog.scan(capture)` for later `join_packets`
- `current`: result as `LazyFrame` if packet-shaped, or **collected `DataFrame`** if aggregate-shaped (aggregates are the small table; do not keep a lazy group_by that would recompute on every continue)
- `joinable`: same meaning as `apply_steps` today (last op was `group_by`/`unique`)

LRU **8** frames. Evict oldest. Log evictions on stderr.

`run(..., frame_id=…)`:

- Lookup; if missing → `error` (expired or unknown)
- If stored `capture` ≠ argument `capture` → `error` (no cross-capture join)
- Plan `steps` apply to `current` (DataFrame → `.lazy()` if needed); `packets_lf` is the stored scan, never the aggregate
- `join_packets` without `joinable` still errors

Timeout / `error`: **do not** store a frame. Timed-out collect threads may still run (existing behavior); they must not block the next `run` and must not publish a partial `frame_id`.

`execute()` stays usable **without** a store (unit tests). Add optional parameters: `packet_preview_rows: int = 5` (packet-shaped default head), and plan `frames`/`join`/arithmetic inside `apply_steps`. The store is a thin wrapper around `execute` + LRU.

### C. Plan ops (required so one `run` can match a Polars script)

**Arithmetic** in `_eval_expr` (no `eval`, no UDFs): `add`, `sub`, `mul`, `div` — each a two-element list of sub-exprs. Use Polars true division. Division by zero → **null** (not an error). Depth still `EXPR_DEPTH_MAX` (32); do not raise the limit in this slice.

**Datetime helper** (required for duration): `total_ms` on a datetime or duration expr → i64 milliseconds. Motivating formula is `max(utc_date_time) - min(utc_date_time)` then `total_ms`, **not** NBA `first_packet`/`last_packet` (those columns do not exist in `PACKET_COLUMNS`).

**Named sibling frames in one plan**, evaluated from the **same input** (scan or `frame_id` current), then `join` in `steps`. Example uses **only `PACKET_COLUMNS`**:

```json
{
  "frames": {
    "by_src": {
      "steps": [
        {"op": "group_by", "keys": ["ip_src"],
         "agg": [{"op": "sum", "col": "ip_len", "alias": "bytes_src"}]}
      ]
    },
    "by_dst": {
      "steps": [
        {"op": "group_by", "keys": ["ip_dst"],
         "agg": [{"op": "sum", "col": "ip_len", "alias": "bytes_dst"}]}
      ]
    }
  },
  "steps": [
    {"op": "from_frame", "frame": "by_src"},
    {"op": "join", "frame": "by_dst", "left_on": ["ip_src"], "right_on": ["ip_dst"], "how": "left"},
    {"op": "with_columns", "columns": [
      {"alias": "bytes_ratio",
       "expr": {"div": [{"col": "bytes_src"}, {"col": "bytes_dst"}]}}
    ]},
    {"op": "sort", "by": ["bytes_src"], "descending": true},
    {"op": "head", "n": 5}
  ]
}
```

Rules:

- Plan op is `from_frame` (not `from`). Tool arg is `frame_id` (not `from`).
- Max **4** named `frames`. No nested `frames`. Unknown name → `error`.
- `join` `how`: same allowlist as `join_packets` (`inner`/`left`/`semi`/`anti`). Same capture only. Require `on` **or** `left_on`+`right_on`.
- Keep `join_packets` for group-then-attach-flags onto packets; still reject `on: ["num"]`.
- `frames` are not a second parquet file.

### D. Extra columns on scan (required for concatenated bulks)

Change `ParquetCatalog.scan` so extra parquet columns are **kept**, not ignored, with a guardrail:

- Always keep `PACKET_COLUMNS` that exist (today’s `CORE_COLUMNS` check unchanged).
- Also keep extra columns present in the file, up to **16**, preferring known CLI tags `filename` and `path` if present, then other extras in schema order.
- Skip extra columns with nested/list/binary dtype (do not put payloads in MCP).
- If extras were dropped, log stderr (count + names), do not fail the scan.

This is **not** an NDT preset. Concatenated conversion output already stores `filename` as a tag; MCP must see it or the motivating query is inexpressible.

### E. Timeout + explain

Keep `COLLECT_TIMEOUT_S = 30`. Do **not** raise it in this slice (slow bugs would hang lab queries for minutes).

Before `_collect`, build the lazy plan. On `TimeoutError`:

- `error` includes `query timed out`
- include `explain` text from `result_lf.explain(optimized=True)` via `_clip_plan`, unless `explain()` itself fails — then omit it
- no `data`, no `frame_id`

Do not claim the worker is cancelled.

## Keep

- `--parquet-dir` / path confinement; stderr logs; stdout is protocol.
- Resources `pcaptoparquet://schema` and `pcaptoparquet://glossary`.
- Presets as sugar on the same lazy scan.
- `join_packets` after `group_by`/`unique`.
- Named MCP prompts: update `GROUP_THEN_JOIN` to say: after `join_packets`, **`group_by`/`unique` so the final frame has no `num`** (aggregate caps, full distinct list). Packet-shaped results are a 5-row sample unless `head`. Do not tell agents “never join_packets”.

## Explicitly out of scope

- Study-named tools/presets (`host_b`, `ndt_throughput`, NBA direction).
- `query(sql)`; filesystem writes; Python UDFs; shell; joining two captures.
- `collect()` of the full packet scan then aggregate in Python.
- Raising `MAX_RESULT_BYTES` or `EXPR_DEPTH_MAX`.
- Raising `COLLECT_TIMEOUT_S`.
- p2p_testbench / M-Lab parquet in CI.
- Converter changes in `pcaptoparquet/` except reading existing `PACKET_COLUMNS` / CLI tag names already used by `e2e_cli.py`.
- A second MCP tool for collect.
- Computing exact `n_rows` when `truncated` (no extra full pass).

## Implementation order

1. `apply_steps` / `_eval_expr`: arithmetic, `total_ms`, `frames` + `from_frame` + `join`. Unit tests on `execute()` only.
2. Packet-shaped default 5-row `data`; aggregate path unchanged. Update `test_packet_head_truncated`.
3. `ParquetCatalog.scan` keeps extras (with tests).
4. `FrameStore` + `run(..., frame_id=)` in `server.py`; tests in `test_mcp_server.py` and a store unit test without the SDK if possible.
5. Timeout envelope + `explain`.
6. `prompts.py`, README MCP section, `mcp.json.example` (document `frame_id`, extra columns, packet preview vs agg `data`).

## Tests (synthetic only)

Extend `tests/test_mcp_queries.py` and `tests/test_mcp_server.py`. Do not read a 13 MiB bulk parquet.

1. **Packet preview** — empty plan / packet-shaped result: `returned_rows == 5`, `truncated` true if more packets existed, `data` is not 200 rows. (Replaces the “empty plan returns 200” expectation.)
2. **Aggregate not preview-capped** — `group_by`/`unique` without `num`: all groups present up to 5000; a 10-group frame is **not** cut to 5. Lab regression: `group_by` + `join_packets` + `unique` on `(ip_src, ip_dst)` still returns the full distinct list in one `execute`.
3. **Arithmetic** — `div`/`sub` on `ip_len`; `/ 0` is null.
4. **`total_ms`** — datetime min/max sub then `total_ms` is i64 ≥ 0 on the tiny fixture.
5. **Aggregate ⋈ aggregate** — the `frames` example (or equivalent) on `_packet_frame()`; no `join_packets`; `bytes_ratio` present.
6. **`join_packets` still works** — existing test green; `join_packets` then `unique` without `num` is aggregate-capped.
7. **Extra `filename`** — parquet with `filename` plus packet cols; `scan` then `group_by` filename has that column.
8. **`frame_id` continue** — first `run` group_by; second `run` with `frame_id` + `sort`/`head` does not require `join_packets`; wrong `capture` with that id errors; unknown id errors.
9. **Timeout** — monkeypatch collect or `timeout_s=0.0` with a slow plan: `error` contains timed out; no fake `data`; `explain` present if the lazy plan exists.
10. **Tools** — `list_tools` is still exactly `list_captures`, `run`.

## Success criteria

- One `run` can express: `group_by`, `join_packets`, `group_by` again, sibling-frame `join`, arithmetic/`total_ms`, `sort`, `head`.
- Packet-shaped tool JSON is preview-sized by default; aggregate JSON still carries the full small answer (distinct lists, mix tables).
- Concatenated bulk parquet with a `filename` tag is queryable without a new tool.
- Continuing via `frame_id` does not rescan packets for aggregate follow-ups (`sort`/`head`/`with_columns` on the stored DataFrame).
- Timeout returns `explain` when possible, not a table.
- No new study-named MCP tool.
- `make check`; `venv_build/bin/pytest tests/test_mcp_queries.py tests/test_mcp_server.py`; then `make test` per repo-dev-workflow.

## What not to cargo-cult from the harness

The external campaign prompt said “do not `join_packets` an NDT flow” because **packet-shaped** results were capped at 200 and still huge in context. The engine fix is: **`join_packets` then reduce so the collected frame has no `num`**, plus **5-row default only while `num` remains**. Do not delete `join_packets`. Do not encode NDT or `host_a`/`conn` in examples or presets.
