# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Polars packet queries over a pcaptoparquet LazyFrame. No MCP imports."""

from __future__ import annotations

from datetime import datetime
from typing import Optional

import polars as pl

DEFAULT_ROW_LIMIT = 50
MAX_ROW_LIMIT = 200
DEFAULT_GROUP_LIMIT = 100

FILTER_COLUMNS = [
    "num",
    "utc_date_time",
    "ip_src",
    "ip_dst",
    "transport_type",
    "transport_src_port",
    "transport_dst_port",
    "transport_syn_flag",
    "transport_ack_flag",
    "transport_rst_flag",
    "transport_fin_flag",
    "e2e_sni",
    "app_type",
    "app_request",
    "app_response",
]


def clamp_row_limit(limit: Optional[int]) -> int:
    """Clamp a raw-row limit to [1, MAX_ROW_LIMIT]."""
    if limit is None:
        return DEFAULT_ROW_LIMIT
    if limit < 1:
        return 1
    return min(limit, MAX_ROW_LIMIT)


def clamp_group_limit(limit: Optional[int]) -> int:
    """Clamp a group-by table size."""
    if limit is None:
        return DEFAULT_GROUP_LIMIT
    if limit < 1:
        return 1
    return min(limit, MAX_ROW_LIMIT)


def frame_to_csv(df: pl.DataFrame) -> str:
    """Render a DataFrame as CSV text."""
    if df.is_empty():
        return "(no rows)\n"
    return df.write_csv()


def _has(lf: pl.LazyFrame, name: str) -> bool:
    return name in lf.collect_schema().names()


def _require(lf: pl.LazyFrame, *names: str) -> None:
    missing = [name for name in names if not _has(lf, name)]
    if missing:
        raise ValueError("missing columns: " + ", ".join(missing))


def _select_existing(lf: pl.LazyFrame, columns: list[str]) -> pl.LazyFrame:
    names = lf.collect_schema().names()
    present = [col for col in columns if col in names]
    if not present:
        raise ValueError("none of the requested columns are present")
    return lf.select(present)


def with_flow_key(lf: pl.LazyFrame) -> pl.LazyFrame:
    """Add a canonical 5-tuple (+ transport_cid) column named flow."""
    _require(
        lf,
        "ip_src",
        "ip_dst",
        "transport_type",
        "transport_src_port",
        "transport_dst_port",
    )
    src = pl.col("ip_src").cast(pl.Utf8)
    dst = pl.col("ip_dst").cast(pl.Utf8)
    sp = pl.col("transport_src_port")
    dp = pl.col("transport_dst_port")
    tt = pl.col("transport_type").cast(pl.Utf8).str.to_lowercase()
    ordered = (
        pl.when(sp < dp)
        .then(
            pl.concat_str(
                [tt, src, sp.cast(pl.Utf8), dst, dp.cast(pl.Utf8)],
                separator="_",
            )
        )
        .otherwise(
            pl.concat_str(
                [tt, dst, dp.cast(pl.Utf8), src, sp.cast(pl.Utf8)],
                separator="_",
            )
        )
    )
    if _has(lf, "transport_cid"):
        ordered = (
            pl.when(pl.col("transport_cid").is_not_null())
            .then(
                pl.concat_str(
                    [ordered, pl.col("transport_cid").cast(pl.Utf8)],
                    separator="_",
                )
            )
            .otherwise(ordered)
        )
    return lf.with_columns(ordered.alias("flow"))


def summarize_capture(lf: pl.LazyFrame, group_limit: Optional[int] = None) -> str:
    """Time range, counts, protocol mix, tunnels, top talkers."""
    n = clamp_group_limit(group_limit)
    parts: list[str] = []
    total = int(lf.select(pl.len()).collect().item())
    parts.append(f"packet_count,{total}\n")

    if _has(lf, "utc_date_time") and total > 0:
        bounds = lf.select(
            pl.col("utc_date_time").min().alias("tmin"),
            pl.col("utc_date_time").max().alias("tmax"),
        ).collect()
        parts.append(
            "tmin,tmax\n" + str(bounds[0, "tmin"]) + "," + str(bounds[0, "tmax"]) + "\n"
        )

    for col in ("transport_type", "app_type", "tunnel"):
        if _has(lf, col):
            mix = lf.group_by(col).len().sort("len", descending=True).head(n).collect()
            parts.append(f"# {col} mix\n" + frame_to_csv(mix))

    for col in ("ip_src", "ip_dst"):
        if _has(lf, col):
            top = lf.group_by(col).len().sort("len", descending=True).head(n).collect()
            parts.append(f"# top {col}\n" + frame_to_csv(top))

    return "\n".join(parts)


def list_flows(lf: pl.LazyFrame, group_limit: Optional[int] = None) -> str:
    """Top-N flows by packet count."""
    n = clamp_group_limit(group_limit)
    keyed = with_flow_key(lf)
    df = keyed.group_by("flow").len().sort("len", descending=True).head(n).collect()
    return frame_to_csv(df)


def filter_packets(
    lf: pl.LazyFrame,
    *,
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
    """Allowlisted predicates, then a fixed column subset and row cap."""
    row_limit = clamp_row_limit(limit)
    expr: Optional[pl.Expr] = None

    def _and(next_expr: pl.Expr) -> None:
        nonlocal expr
        expr = next_expr if expr is None else (expr & next_expr)

    if ip_src is not None:
        _require(lf, "ip_src")
        _and(pl.col("ip_src").cast(pl.Utf8) == ip_src)
    if ip_dst is not None:
        _require(lf, "ip_dst")
        _and(pl.col("ip_dst").cast(pl.Utf8) == ip_dst)
    if transport_src_port is not None:
        _require(lf, "transport_src_port")
        _and(pl.col("transport_src_port") == transport_src_port)
    if transport_dst_port is not None:
        _require(lf, "transport_dst_port")
        _and(pl.col("transport_dst_port") == transport_dst_port)
    if app_type is not None:
        _require(lf, "app_type")
        _and(pl.col("app_type").cast(pl.Utf8) == app_type)
    if transport_type is not None:
        _require(lf, "transport_type")
        _and(pl.col("transport_type").cast(pl.Utf8) == transport_type)
    if e2e_sni is not None:
        _require(lf, "e2e_sni")
        _and(pl.col("e2e_sni") == e2e_sni)
    if time_from is not None:
        _require(lf, "utc_date_time")
        _and(pl.col("utc_date_time") >= time_from)
    if time_to is not None:
        _require(lf, "utc_date_time")
        _and(pl.col("utc_date_time") <= time_to)

    filtered = lf.filter(expr) if expr is not None else lf
    df = _select_existing(filtered, FILTER_COLUMNS).head(row_limit).collect()
    return frame_to_csv(df)


def sni_table(lf: pl.LazyFrame, group_limit: Optional[int] = None) -> str:
    """Non-null e2e_sni values, top-N by packet count."""
    _require(lf, "e2e_sni")
    n = clamp_group_limit(group_limit)
    df = (
        lf.filter(pl.col("e2e_sni").is_not_null() & (pl.col("e2e_sni") != ""))
        .group_by("e2e_sni")
        .len()
        .sort("len", descending=True)
        .head(n)
        .collect()
    )
    return frame_to_csv(df)


def app_messages(lf: pl.LazyFrame, limit: Optional[int] = None) -> str:
    """DNS/HTTP app_request / app_response rows."""
    _require(lf, "app_type", "app_request", "app_response")
    row_limit = clamp_row_limit(limit)
    df = (
        lf.filter(
            pl.col("app_type").cast(pl.Utf8).is_in(["DNS", "HTTP"])
            & (
                pl.col("app_request").is_not_null()
                | pl.col("app_response").is_not_null()
            )
        )
        .select(
            [
                col
                for col in (
                    "num",
                    "utc_date_time",
                    "app_type",
                    "app_request",
                    "app_response",
                )
                if _has(lf, col)
            ]
        )
        .head(row_limit)
        .collect()
    )
    return frame_to_csv(df)


def tcp_setup(
    lf: pl.LazyFrame,
    *,
    syn: Optional[bool] = None,
    ack: Optional[bool] = None,
    rst: Optional[bool] = None,
    fin: Optional[bool] = None,
    limit: Optional[int] = None,
) -> str:
    """TCP rows filtered by SYN/ACK/RST/FIN booleans. Default: SYN set."""
    _require(lf, "transport_type")
    row_limit = clamp_row_limit(limit)
    filtered = lf.filter(pl.col("transport_type").cast(pl.Utf8) == "TCP")
    if syn is None and ack is None and rst is None and fin is None:
        syn = True
    flag_map = {
        "transport_syn_flag": syn,
        "transport_ack_flag": ack,
        "transport_rst_flag": rst,
        "transport_fin_flag": fin,
    }
    expr: Optional[pl.Expr] = None
    for col, wanted in flag_map.items():
        if wanted is None:
            continue
        _require(lf, col)
        next_expr = pl.col(col) == wanted
        expr = next_expr if expr is None else (expr & next_expr)
    if expr is not None:
        filtered = filtered.filter(expr)
    df = _select_existing(filtered, FILTER_COLUMNS).head(row_limit).collect()
    return frame_to_csv(df)


def quic_initials(lf: pl.LazyFrame, limit: Optional[int] = None) -> str:
    """Rows with transport_pkn set (visible QUIC/SCTP/ICMP numbers).

    Short-header QUIC packet numbers are not decoded and will not appear.
    """
    _require(lf, "transport_pkn")
    row_limit = clamp_row_limit(limit)
    cols = [
        col
        for col in (
            "num",
            "utc_date_time",
            "ip_src",
            "ip_dst",
            "transport_type",
            "app_type",
            "transport_pkn",
            "e2e_sni",
        )
        if _has(lf, col)
    ]
    df = (
        lf.filter(pl.col("transport_pkn").is_not_null())
        .select(cols)
        .head(row_limit)
        .collect()
    )
    return frame_to_csv(df)
