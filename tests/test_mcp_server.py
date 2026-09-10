# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Smoke test that the MCP server loads with the SDK."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
            "transport_type": ["TCP"],
        }
    ).write_parquet(path)


def _tool_text(result: Any) -> str:
    content = result.content
    if isinstance(content, list) and content:
        text = getattr(content[0], "text", None)
        if text is not None:
            return str(text)
    return str(content)


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
            assert names == ["list_captures", "run"]
            listed = await client.call_tool("list_captures", {})
            assert "cap.parquet" in _tool_text(listed)
            counted = await client.call_tool(
                "run",
                {
                    "capture": "cap.parquet",
                    "plan": {
                        "steps": [
                            {
                                "op": "group_by",
                                "keys": ["transport_type"],
                                "agg": [{"op": "len", "alias": "n"}],
                            }
                        ]
                    },
                },
            )
            payload = json.loads(_tool_text(counted))
            assert payload["data"][0][1] == 1
            assert payload["truncated"] is False
            assert "frame_id" in payload
            continued = await client.call_tool(
                "run",
                {
                    "capture": "cap.parquet",
                    "frame_id": payload["frame_id"],
                    "plan": {
                        "steps": [
                            {"op": "sort", "by": ["n"], "descending": True},
                            {"op": "head", "n": 1},
                        ]
                    },
                },
            )
            cont = json.loads(_tool_text(continued))
            assert "error" not in cont
            assert cont["returned_rows"] == 1
            assert "frame_id" in cont
            unknown = await client.call_tool(
                "run",
                {
                    "capture": "cap.parquet",
                    "frame_id": "deadbeefdeadbeef",
                    "plan": {"steps": []},
                },
            )
            assert "error" in json.loads(_tool_text(unknown))
            preset = await client.call_tool(
                "run",
                {"capture": "cap.parquet", "preset": "summarize_capture"},
            )
            assert "packet_count" in _tool_text(preset)
            denied = await client.call_tool(
                "run",
                {
                    "capture": "../secret.parquet",
                    "plan": {"steps": []},
                },
            )
            assert "error" in json.loads(_tool_text(denied))
            schema = await client.read_resource("pcaptoparquet://schema")
            assert "transport_pkn" in str(schema)

    anyio.run(_check)
