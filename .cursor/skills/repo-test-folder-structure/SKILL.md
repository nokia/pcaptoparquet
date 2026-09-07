---
name: repo-test-folder-structure
description: >-
  Explains the tests/ layout: tests/data captures, tests/config protocol
  extensions, tests/callbacks, tests/out artifacts, and test_cli/. Use when
  adding or running tests, wiring PCAP fixtures, or when the user mentions
  tests/data, tests/out, or generate_outputs.
---

# Test folder structure (this project)

## Layout

```
tests/
├── test_unit.py           # E2EPacket unit tests
├── test_quic_initial.py   # QUIC Initial unprotect / transport_pkn
├── test_module.py         # Functional PCAP → parquet/json/txt
├── test_utils.py          # configure_dirs(), generate_outputs()
├── data/                  # Input captures (read-only)
├── config/                # Optional JSON maps + extension modules
├── callbacks/             # Post-processing Polars callbacks
└── out/                   # Generated outputs (not source of truth)
test_cli/
└── test_cli.py            # CLI subprocess tests (not in tox pytest tests/)
```

Resolve paths via `tests/test_utils.py` `configure_dirs()`:

| Key | Path | Role |
|-----|------|------|
| `ddir` | `tests/data` | Input `.pcap` / `.pcap.gz` / `.pcapng.gz` |
| `odir` | `tests/out` | Conversion outputs |
| `bdir` | `tests/benchmark` | Optional perf logs |
| `cdir` | `tests/config` | JSON protocol maps |

`make clean-test` removes `tests/out` and `.tox`.

## `tests/data` — inputs

- **Read-only.** Tests must not modify files here.
- Functional captures live under `tests/data/00_functional/`:

| Folder | Contents |
|--------|----------|
| `00_file_formats/` | pcap vs pcapng, size variants |
| `01_encapsulations/` | null, SLL, Ethernet/VLAN |
| `02_tunnels/` | GTP, VXLAN, MPLS |
| `03_ip_versions/` | IPv4 / IPv6 |
| `04_transports/` | UDP, TCP, GQUIC, IETF QUIC, SCTP |
| `05_applications/` | DNS, ICMP, HTTP, HTTPS, GQUIC, IETF QUIC, SIP |
| `99_others/` | pcapng odds and ends |

- Paths in `test_module.py` are relative to those folders (files are typically `.gz`).
- QUIC fixtures: `04_transports/20_udp_gquic`, `21_udp_ietf_quic`; `05_applications/30.gquic`, `31.ietf_quic_draft29`, `32.ietf_quic_v1`.

## `tests/config` and `tests/callbacks`

- JSON maps (`volte.cfg`, `twamplight.cfg`) load extra `decode` modules from `tests/config/modules/`.
- Callbacks (`tests/callbacks/*.py`) export `process_pcap_polars` and are passed to `E2EConfig(callbackpath=...)`.
- See **repo-protocol-decoder** for the module contract.

## `tests/out` — outputs

Mirrors the `data/` subtree. Written by `generate_outputs()` (txt, json, parquet, plus optional `.profile`). Treat as **regenerable**.

## Adding a new capture

1. Place the file under `tests/data/00_functional/<folder>/`.
2. Add a `test_*` function in `tests/test_module.py` that calls `generate_outputs(...)`.
3. Run that test, then `make check`.
