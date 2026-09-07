---
name: repo-fast-test-selection
description: >-
  Selects the minimal pytest subset for a code change in pcaptoparquet. Use when
  iterating on pcaptoparquet/, running tests during development, choosing which
  tests to run, or when the user mentions pytest, tox, or make test.
---

# Fast test selection (this project)

## Default dev loop

- **Targeted:** `venv_build/bin/pytest tests/test_foo.py -k somename --verbose`
- **Compliance:** `make check` after non-trivial code changes, then `make test` (`tox` → `pytest tests/`).
- CLI tests under `test_cli/` are linted/type-checked by `make check` but are **not** in the tox `pytest tests/` command. Run them with `venv_build/bin/pytest test_cli/` when the CLI changes.

There is no pytest `slow` marker in this repository. `make test` runs the full `tests/` suite, including functional PCAP conversions.

## Module → critical tests

Run the listed files (or narrower `-k` filters) for the area you changed. If multiple areas changed, union the lists.

| Changed module(s) | Run these tests |
|-------------------|-----------------|
| `pcaptoparquet/e2e_quic.py` | `tests/test_quic_initial.py` |
| `pcaptoparquet/e2e_packet.py` | `tests/test_unit.py` |
| `pcaptoparquet/e2e_ping.py`, `e2e_dns.py`, `e2e_http.py`, `e2e_https.py` | `tests/test_module.py` tests under `05_applications/` |
| `pcaptoparquet/e2e_pcap.py`, `e2e_parallel.py`, `e2e_config.py` | `tests/test_module.py` (functional captures) |
| `pcaptoparquet_cli.py`, `pcaptoparquet/e2e_cli.py` | `test_cli/test_cli.py` |
| `tests/config/modules/*.py` | matching `test_module.py` captures that pass `--config` / `E2EConfig(configpath=...)` |

Example targeted run:

```bash
venv_build/bin/pytest tests/test_quic_initial.py tests/test_unit.py -v
```

## When to run the full suite

Run `make test` (not only a targeted file) when you change:

- PCAP ingest / export (`E2EPcap`, parquet/CSV/JSON writers)
- `E2EConfig` port maps or callback loading
- `E2EPacket` schema (`_decoder_meta`) or header decoding shared by all protocols
- Default application decoders that run on UDP/TCP 443 or well-known ports

## Adding new tests

- **Pure logic / synthetic packets** — add `tests/test_*.py` (unittest or pytest); included in `make test`.
- **PCAP conversion** — add a fixture under `tests/data/` and a function in `tests/test_module.py` that calls `generate_outputs()`.
- **CLI** — add cases in `test_cli/test_cli.py`.

## Quick checklist (before finishing a change)

- [ ] Ran the mapped tests for the module(s) you edited.
- [ ] Ran `make check`.
- [ ] If ingest/export/schema/CLI changed: ran `make test` (and `pytest test_cli/` for CLI).
