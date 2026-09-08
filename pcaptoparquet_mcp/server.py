# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""stdio MCP server over a confined pcaptoparquet Parquet directory."""

from __future__ import annotations

import argparse
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Optional

from pcaptoparquet_mcp import prompts, queries, resources
from pcaptoparquet_mcp.catalog import CatalogError, ParquetCatalog

_LOG = logging.getLogger("pcaptoparquet_mcp")


def build_parser() -> argparse.ArgumentParser:
    """CLI for the stdio server."""
    parser = argparse.ArgumentParser(
        prog="pcaptoparquet-mcp",
        description=(
            "Packet-aware MCP server for a directory of pcaptoparquet Parquet files."
        ),
    )
    parser.add_argument(
        "--parquet-dir",
        default=os.environ.get("PCAPTOPARQUET_PARQUET_DIR"),
        help=("Directory of Parquet files. " "Defaults to PCAPTOPARQUET_PARQUET_DIR."),
    )
    return parser


def _tool_error(exc: BaseException) -> str:
    return f"error: {exc}"


def build_server(catalog: ParquetCatalog) -> Any:
    """Register tools, resources, and prompts. Imports the MCP SDK here."""
    try:
        from mcp.server import MCPServer
    except ImportError as exc:
        raise ImportError(
            "The MCP SDK is required. Install with: " "pip install 'pcaptoparquet[mcp]'"
        ) from exc

    mcp = MCPServer("pcaptoparquet")

    def _query(capture: str, fn: Callable[..., str], **kwargs: Any) -> str:
        try:
            lf = catalog.scan(capture)
            return fn(lf, **kwargs)
        except (CatalogError, ValueError) as exc:
            return _tool_error(exc)
        except Exception as exc:
            _LOG.exception("query failed")
            return _tool_error(exc)

    @mcp.tool()
    def list_captures() -> str:
        """List relative Parquet paths, size, mtime, and row counts."""
        try:
            return queries.frame_to_csv(catalog.list_captures())
        except CatalogError as exc:
            return _tool_error(exc)

    @mcp.tool()
    def summarize_capture(capture: str, group_limit: Optional[int] = None) -> str:
        """Time range, packet count, protocol mix, tunnels, top talkers.

        capture is a path relative to the Parquet directory (file or subdirectory).
        """
        return _query(capture, queries.summarize_capture, group_limit=group_limit)

    @mcp.tool()
    def list_flows(capture: str, group_limit: Optional[int] = None) -> str:
        """Top flows by packet count (5-tuple plus transport_cid when set).

        transport_pkn is not a flow key. capture is relative to the Parquet directory.
        """
        return _query(capture, queries.list_flows, group_limit=group_limit)

    @mcp.tool()
    def filter_packets(
        capture: str,
        ip_src: Optional[str] = None,
        ip_dst: Optional[str] = None,
        transport_src_port: Optional[int] = None,
        transport_dst_port: Optional[int] = None,
        app_type: Optional[str] = None,
        transport_type: Optional[str] = None,
        e2e_sni: Optional[str] = None,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: Optional[int] = None,
    ) -> str:
        """Filter packets with allowlisted predicates. Returns a column subset.

        capture is a path relative to the Parquet directory (file or subdirectory).
        """
        return _query(
            capture,
            queries.filter_packets,
            ip_src=ip_src,
            ip_dst=ip_dst,
            transport_src_port=transport_src_port,
            transport_dst_port=transport_dst_port,
            app_type=app_type,
            transport_type=transport_type,
            e2e_sni=e2e_sni,
            time_from=time_from,
            time_to=time_to,
            limit=limit,
        )

    @mcp.tool()
    def sni_table(capture: str, group_limit: Optional[int] = None) -> str:
        """Non-null e2e_sni values. TLS ClientHello and IETF QUIC v1 Initial only."""
        return _query(capture, queries.sni_table, group_limit=group_limit)

    @mcp.tool()
    def app_messages(capture: str, limit: Optional[int] = None) -> str:
        """DNS and HTTP app_request / app_response rows."""
        return _query(capture, queries.app_messages, limit=limit)

    @mcp.tool()
    def tcp_setup(
        capture: str,
        syn: Optional[bool] = None,
        ack: Optional[bool] = None,
        rst: Optional[bool] = None,
        fin: Optional[bool] = None,
        limit: Optional[int] = None,
    ) -> str:
        """TCP rows by SYN/ACK/RST/FIN booleans (not a flags bitmask). Default SYN."""
        return _query(
            capture,
            queries.tcp_setup,
            syn=syn,
            ack=ack,
            rst=rst,
            fin=fin,
            limit=limit,
        )

    @mcp.tool()
    def quic_initials(capture: str, limit: Optional[int] = None) -> str:
        """Rows with transport_pkn set. Short-header QUIC packet numbers are absent."""
        return _query(capture, queries.quic_initials, limit=limit)

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
        """Workflow for TCP handshake failures."""
        return prompts.TCP_SETUP

    @mcp.prompt()
    def sni_in_capture() -> str:
        """Workflow for listing SNI in a capture."""
        return prompts.SNI_IN_CAPTURE

    @mcp.prompt()
    def traffic_mix() -> str:
        """Workflow for transport and application mix."""
        return prompts.TRAFFIC_MIX

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
