# Redesign pcaptoparquet MCP as a versatile Polars capture engine

Work only in **this** repository (`pcaptoparquet`). Follow `.cursor/rules` (Polars for tabular work, `make venv` / `make check` / `make test`). Do not add NBA, tcptrace, or p2p_testbench metrics as MCP tools.

## Goal

Give agents a **read-only, packet-aware dataframe engine** over pcaptoparquet Parquet: discover captures, inspect this schema, filter, aggregate, and (when needed) join **within one capture**, then return a **small result**.

- The **host/agent** asks an arbitrary question that fits `schema.md` / `PACKET_COLUMNS`.
- The **server** runs it with **Polars lazy scans** and returns counts, distinct lists, or a capped sample—not the capture.
- Token cost and latency should track **result size**, not **how many packets were scanned**.

This must stay useful for *any* schema-valid question (mix, SNI, flags, ports, tunnels, group/count/distinct, “group then attach flags back onto packets”). It must **not** grow a new tool per study (`tcp_servers`, `top_talkers_v2`, `host_b`, …).

**SQL is not the product.** Do not replace the MCP with `query(capture, sql)` (Polars SQL dialect, `JOIN` banned, named tools deleted). That is narrower than a packet-aware menu and harder for agents than Polars operations. “Like an SQL engine” meant **generality + aggregation off-prompt**, not a SQL API.

## Why both extremes are wrong

**Closed named menu (committed tools):** `filter_packets`, `tcp_setup`, `app_messages`, `quic_initials` dump CSV with `MAX_ROW_LIMIT = 200` and no offset. `summarize_capture`, `list_flows`, `sni_table` are useful aggregations but cannot express a new grouping. Agents that need a full-table count or distinct list still pull packet rows into the model.

**SQL-only MCP (uncommitted working tree, do not keep as the design):** `list_captures` + `query(sql)` on table `packets`, `SELECT`/`WITH` only, `JOIN` rejected, 200-row / 32KiB caps. Named shortcuts were removed. Agents cannot join a per-`(ip_src, ip_dst)` aggregation back to packets; they approximate in SQL or invent extra IPs. External harness: 10KB/100KB NBA-style `host_b` still matched, 1MB did not (71 vs 57 servers)—same failure mode as a shell Polars script that skipped the join-back.

MCP should offer the **same engine as a Polars script** (lazy scan, group_by, join, collect a small frame), not a packet dump and not a SQL sandbox.

## Target shape (Polars MCP, this schema)

Keep confinement and discovery. Expose **composable Polars operations** (preferred) or **one structured plan** (JSON: filter / with_columns / group_by / agg / join / head)—not SQL text. Shortcuts stay as sugar on the same lazy scan.

**Keep (behavior, not necessarily exact APIs):**

- `--parquet-dir` / `PCAPTOPARQUET_PARQUET_DIR`; relative capture paths; no path escape (`ParquetCatalog`).
- Resources `pcaptoparquet://schema` and `pcaptoparquet://glossary`.
- Stdio MCP; logs on stderr; stdout is protocol.
- Optional extra `pcaptoparquet[mcp]`; converter code in `pcaptoparquet/` stays separate.
- Packet-aware shortcuts (do **not** delete unless they become thin wrappers around the general engine): `summarize_capture`, `list_flows`, `sni_table`, capped `filter_packets` / `tcp_setup` / `app_messages` / `quic_initials`. They answer mix/talkers/SNI/samples; they are not a substitute for general group/join.

**Discovery:**

- `list_captures` (or equivalent): relative path, size, mtime, **row count from Parquet metadata/footer** when possible—not a full `scan_parquet` + `select(len)` if the footer already has `num_rows`.
- Schema is the pcaptoparquet packet table (`PACKET_COLUMNS` / `schema.md`). Extra columns: keep current `extra_columns="ignore"` policy unless you have a better documented rule.

**Execute (the important new surface):**

Prefer small composable tools over one SQL string, for example:

- `filter` — allowlisted predicates and/or a documented expression subset on this schema.
- `aggregate` / `group_by` — keys + aggregations (`len`, `n_unique`, `min`, `max`, `sum`, `any`/`all` on booleans).
- `with_columns` — documented expressions (booleans, comparisons, `when/then` for flags and ports)—still not Python UDFs.
- `join` — **same capture only** (self-join / join aggregation back to packets). Do not join a second capture or scan arbitrary files unless you explicitly design and test it.
- `head` / sample with projection; result cap + `truncated`.
- Optional `explain` so the agent sees the lazy plan / pushdown, not extra packet rows.

A single JSON plan tool is acceptable if it is the same operations (not SQL). Do **not** add `query(sql)` as the only execute path. If you keep SQL at all, it is an optional extra beside the Polars surface, and it must not ban same-capture joins that `join` already allows.

**Guardrails (tokens + safety):**

- Read-only. No writes, no Python UDFs, no filesystem, no path escape.
- Timeout on collect.
- **Hard cap on response bytes and/or rows** (document defaults). Full-table dumps must truncate with `truncated`, never send a capture into the model.
- Aggregations that return a few rows must **not** be limited as if they were packet dumps (a 200-row cap on `SELECT *` is fine; a 200-row cap that hides a 57-IP distinct list is a bug if the list fits the byte cap).
- Prefer compact JSON or a tight CSV for the **result table**. Do not attach unused wide column subsets to aggregates.
- Projection + predicate pushdown via `pl.scan_parquet`. Do not `collect()` the full frame then aggregate in Python.

**Named prompts:** rewrite `pcaptoparquet_mcp/prompts.py` as **Polars workflows** on this schema (handshake flags, SNI, mix, group-then-join-back), not “paste this SQL” and not “call `tcp_setup` then eyeball 200 CSV rows.”

## Explicitly out of scope

- Do **not** add tools named for a particular study (`tcp_servers`, `nba_direction`, `host_b`, …). Clients compose filter / group / join.
- Do **not** make Polars SQL the MCP API (and do not ship `JOIN`-banned SQL as the replacement for named tools).
- Do **not** convert PCAP inside MCP.
- Do **not** introduce pandas. Follow `global-polars-development`.
- Do **not** weaken catalog path confinement.

## Implementation notes

- Working tree may already contain the SQL-only `query` rewrite (`pcaptoparquet_mcp/server.py`, `queries.py`, tests, README). Treat that as the wrong target: restore shortcuts, add the Polars surface, drop SQL-as-the-only-tool.
- Primary code: `pcaptoparquet_mcp/queries.py`, `server.py`, `catalog.py`, `prompts.py`, `tests/test_mcp_queries.py`, `tests/test_mcp_server.py`.
- Update README MCP section and `mcp.json.example` if the tool list changes.
- `list_captures` row counts: prefer parquet footer metadata.
- Tests: path traversal still fails; aggregations return small results without depending on a 200-row packet dump; same-capture join of a group-by back to packets works; samples truncate with `truncated`; invalid input returns `error: …` without crashing the server; shortcut tools still work.
- After changes: `make check` and MCP tests (`tests/test_mcp_queries.py`, `tests/test_mcp_server.py`) plus whatever `repo-fast-test-selection` maps to these modules.

## Success criteria

An agent can answer **arbitrary** schema-valid questions (not only mix/SNI/SYN samples) with a few Polars tool calls whose payloads look like the answer (counts, small grouped tables, distinct lists, or a capped sample). Same-capture “aggregate then join back” is expressible without inventing SQL. Adding a new analysis in a client repo must **not** require a new MCP tool in this repo, and must **not** require the client to speak Polars SQL.
