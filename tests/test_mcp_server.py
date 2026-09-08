# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Smoke test that the MCP server loads with the SDK."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import anyio
import polars as pl
import pytest

from pcaptoparquet_mcp.catalog import ParquetCatalog
from pcaptoparquet_mcp.server import build_parser, build_server, main

mcp = pytest.importorskip("mcp")


def _minimal_parquet(path: Path) -> None:
    pl.DataFrame(
        {
            "num": [1],
            "utc_date_time": [datetime(2024, 1, 1, tzinfo=timezone.utc)],
        }
    ).write_parquet(path)


def test_parser_requires_dir_via_main(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("PCAPTOPARQUET_PARQUET_DIR", raising=False)
    parser = build_parser()
    args = parser.parse_args([])
    assert args.parquet_dir is None
    with pytest.raises(SystemExit) as exited:
        main([])
    assert exited.value.code == 2
    with pytest.raises(SystemExit) as missing:
        main(["--parquet-dir", str(tmp_path / "nope")])
    assert missing.value.code == 2


def test_server_tools_and_resources(tmp_path: Path) -> None:
    _minimal_parquet(tmp_path / "cap.parquet")
    catalog = ParquetCatalog(tmp_path)
    server = build_server(catalog)

    async def _check() -> None:
        from mcp import Client

        async with Client(server) as client:
            tools = await client.list_tools()
            names = sorted(tool.name for tool in tools.tools)
            assert names == [
                "app_messages",
                "filter_packets",
                "list_captures",
                "list_flows",
                "quic_initials",
                "sni_table",
                "summarize_capture",
                "tcp_setup",
            ]
            listed = await client.call_tool("list_captures", {})
            text = str(listed.content)
            assert "cap.parquet" in text
            schema = await client.read_resource("pcaptoparquet://schema")
            schema_text = str(schema)
            assert "transport_pkn" in schema_text

    anyio.run(_check)
