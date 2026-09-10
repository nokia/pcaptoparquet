# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""stdio MCP server over a confined pcaptoparquet Parquet directory."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any, Optional

from pcaptoparquet_mcp import prompts, queries, resources
from pcaptoparquet_mcp.catalog import CatalogError, ParquetCatalog
from pcaptoparquet_mcp.frames import FrameStore, FrameTable

_LOG = logging.getLogger("pcaptoparquet_mcp")


def build_parser() -> argparse.ArgumentParser:
    """CLI for the stdio server."""
    parser = argparse.ArgumentParser(
        prog="pcaptoparquet-mcp",
        description="Read-only Polars MCP server for pcaptoparquet Parquet files.",
    )
    parser.add_argument(
        "--parquet-dir",
        default=os.environ.get("PCAPTOPARQUET_PARQUET_DIR"),
        help=("Directory of Parquet files. Defaults to PCAPTOPARQUET_PARQUET_DIR."),
    )
    return parser


def run_capture(
    catalog: ParquetCatalog,
    store: FrameStore,
    *,
    capture: str,
    plan: Any = None,
    preset: Optional[str] = None,
    args: Any = None,
    explain: bool = False,
    frame_id: Optional[str] = None,
) -> dict[str, Any]:
    """Execute a plan or preset; store a successful frame for frame_id continue."""
    joinable = False
    if frame_id:
        stored = store.get(str(frame_id))
        if stored is None:
            return queries.error_envelope("unknown or expired frame_id")
        if stored.capture != capture:
            return queries.error_envelope("frame_id does not belong to this capture")
        lf = store.as_lazy(stored)
        packets_lf = stored.packets_lf
        joinable = stored.joinable
    else:
        try:
            lf = catalog.scan(capture)
        except CatalogError as exc:
            return queries.error_envelope(str(exc))
        except Exception as exc:
            _LOG.exception("scan failed")
            return queries.error_envelope(str(exc))
        packets_lf = lf
    outcome = queries.run_plan(
        lf,
        plan=plan,
        preset=preset,
        args=args,
        packets_lf=packets_lf,
        explain=explain,
        joinable=joinable,
    )
    envelope = outcome.envelope
    if "error" in envelope:
        return envelope
    current: Optional[FrameTable]
    if outcome.result_lf is not None:
        current = outcome.result_lf
    else:
        current = outcome.collected
    if current is None:
        return envelope
    envelope["frame_id"] = store.put(
        capture=capture,
        packets_lf=packets_lf,
        current=current,
        joinable=outcome.joinable,
    )
    return envelope


def build_server(catalog: ParquetCatalog) -> Any:
    """Register tools, resources, and prompts. Imports the MCP SDK here."""
    try:
        from mcp.server import MCPServer
    except ImportError as exc:
        raise ImportError(
            "The MCP SDK is required. Install with: pip install 'pcaptoparquet[mcp]'"
        ) from exc

    mcp = MCPServer("pcaptoparquet")
    store = FrameStore()

    @mcp.tool()
    def list_captures() -> str:
        """List relative Parquet paths, size, mtime, and metadata row counts."""
        try:
            return queries.frame_to_csv(catalog.list_captures())
        except CatalogError as exc:
            return queries.dumps_envelope({"error": str(exc)})

    @mcp.tool()
    def run(
        capture: str,
        plan: Optional[Any] = None,
        preset: Optional[str] = None,
        args: Optional[Any] = None,
        explain: bool = False,
        frame_id: Optional[str] = None,
    ) -> str:
        """Lazy Polars plan or preset on one capture (schema.md / PACKET_COLUMNS).

        Ops: filter, with_columns, select, unique, sort, group_by, join_packets,
        join, from_frame, head. Arithmetic add/sub/mul/div; total_ms. Named plan
        frames (max 4) then join. Presets: summarize_capture, list_flows, sni_table,
        filter_packets, tcp_setup, app_messages, quic_initials, endpoints,
        conversations, io_stat. Prefer one run after list_captures. Extra tags
        (filename, path, …) are kept up to 16. Packet-shaped data is a 5-row
        preview (head to see more, cap 200); aggregates cap 5000; JSON 32KiB;
        30s collect timeout. frame_id continues a stored result of this capture.
        """
        payload = run_capture(
            catalog,
            store,
            capture=capture,
            plan=plan,
            preset=preset,
            args=args,
            explain=explain,
            frame_id=frame_id,
        )
        return queries.dumps_envelope(payload)

    @mcp.resource("pcaptoparquet://schema")
    def schema_resource() -> str:
        """pcaptoparquet Parquet column schema."""
        return resources.load_schema_markdown()

    @mcp.resource("pcaptoparquet://glossary")
    def glossary_resource() -> str:
        """Field caveats for packet-aware queries."""
        return resources.GLOSSARY

    @mcp.prompt()
    def diagnose_tcp_setup() -> str:
        """One run() plan for TCP handshake flags."""
        return prompts.TCP_SETUP

    @mcp.prompt()
    def sni_in_capture() -> str:
        """One run() plan for listing SNI."""
        return prompts.SNI_IN_CAPTURE

    @mcp.prompt()
    def traffic_mix() -> str:
        """One run() plan for transport and application mix."""
        return prompts.TRAFFIC_MIX

    @mcp.prompt()
    def group_then_join() -> str:
        """One run() plan that groups, then joins back to packets."""
        return prompts.GROUP_THEN_JOIN

    @mcp.prompt()
    def who_talks() -> str:
        """One run() preset for endpoints or conversations."""
        return prompts.WHO_TALKS

    return mcp


def main(argv: Optional[list[str]] = None) -> None:
    """Parse args, fail fast on a bad data root, run stdio (stdout is protocol)."""
    logging.basicConfig(stream=sys.stderr, level=logging.INFO)
    parser = build_parser()
    args = parser.parse_args(argv)
    parquet_dir = args.parquet_dir
    if not parquet_dir:
        print(
            "error: --parquet-dir or PCAPTOPARQUET_PARQUET_DIR is required",
            file=sys.stderr,
        )
        raise SystemExit(2)
    try:
        catalog = ParquetCatalog(Path(parquet_dir))
    except CatalogError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    try:
        mcp = build_server(catalog)
    except ImportError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
