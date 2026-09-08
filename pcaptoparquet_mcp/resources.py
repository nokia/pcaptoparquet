# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Static MCP resources: schema.md and a short field glossary."""

from importlib.resources import files
from pathlib import Path

GLOSSARY = """\
pcaptoparquet Parquet glossary

- Each row is one decoded packet. Application payloads are usually encrypted.
- not_decoded_data is never written to Parquet (callbacks may see it in memory).
- transport_pkn: visible packet/message number without session keys (SCTP DATA,
  ICMP echo, GQUIC public header, IETF QUIC v1 Initial after header protection).
  It is not TCP sequence (that is transport_seq). Short-header QUIC packet
  numbers are not decoded.
- transport_spin: QUIC short-header spin bit.
- e2e_sni: SNI from TLS ClientHello and IETF QUIC v1 Initial CRYPTO frames only.
- tunnel: GTP-U and VxLAN when present. L2TPv2, L2TPv3, and GRE are experimental.
- Query tools require a capture path relative to the Parquet directory (one
  file or a subdirectory). There is no whole-tree union.
"""


def load_schema_markdown() -> str:
    """Return the converter schema.md (repo root, or the wheel copy)."""
    repo_schema = Path(__file__).resolve().parents[1] / "schema.md"
    if repo_schema.is_file():
        return repo_schema.read_text(encoding="utf-8")
    return (
        files("pcaptoparquet_mcp")
        .joinpath("data")
        .joinpath("schema.md")
        .read_text(encoding="utf-8")
    )
