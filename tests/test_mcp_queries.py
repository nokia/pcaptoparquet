# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for pcaptoparquet_mcp catalog and packet queries."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import polars as pl
import pytest

from pcaptoparquet_mcp.catalog import CatalogError, ParquetCatalog
from pcaptoparquet_mcp.queries import (
    MAX_ROW_LIMIT,
    app_messages,
    clamp_row_limit,
    filter_packets,
    list_flows,
    quic_initials,
    sni_table,
    summarize_capture,
    tcp_setup,
    with_flow_key,
)
from pcaptoparquet_mcp.resources import load_schema_markdown


def _utc(year: int, month: int, day: int, hour: int = 0) -> datetime:
    return datetime(year, month, day, hour, tzinfo=timezone.utc)


def _packet_frame() -> pl.DataFrame:
    return pl.DataFrame(
        {
            "num": [1, 2, 3, 4, 5],
            "utc_date_time": [
                _utc(2024, 1, 1, 0),
                _utc(2024, 1, 1, 1),
                _utc(2024, 1, 1, 2),
                _utc(2024, 1, 1, 3),
                _utc(2024, 1, 1, 4),
            ],
            "ip_src": ["10.0.0.1", "10.0.0.2", "10.0.0.1", "10.0.0.1", "10.0.0.9"],
            "ip_dst": ["8.8.8.8", "10.0.0.1", "8.8.8.8", "1.1.1.1", "8.8.8.8"],
            "transport_type": ["UDP", "TCP", "UDP", "TCP", "UDP"],
            "transport_src_port": [53000, 443, 53000, 40000, 123],
            "transport_dst_port": [53, 50000, 53, 443, 53],
            "transport_syn_flag": [None, True, None, True, None],
            "transport_ack_flag": [None, False, None, True, None],
            "transport_rst_flag": [None, False, None, False, None],
            "transport_fin_flag": [None, False, None, False, None],
            "transport_cid": [None, None, None, None, None],
            "transport_pkn": [None, None, None, None, 7],
            "e2e_sni": [None, "example.com", None, "example.com", None],
            "app_type": ["DNS", "HTTPS", "DNS", "HTTPS", "QUIC"],
            "app_request": ["A www.example.com", None, "A ntp", None, None],
            "app_response": [None, None, "1.2.3.4", None, None],
            "tunnel": [None, None, "GTP-U", None, None],
            "custom_tag": ["x", "x", "x", "x", "x"],
        }
    )


def _write_parquet(path: Path, extra: bool = True) -> Path:
    df = _packet_frame()
    if not extra:
        df = df.drop("custom_tag")
    path.parent.mkdir(parents=True, exist_ok=True)
    df.write_parquet(path)
    return path


def test_schema_md_matches_repo_root() -> None:
    root = Path(__file__).resolve().parents[1] / "schema.md"
    assert load_schema_markdown() == root.read_text(encoding="utf-8")
    packaged = root.parent / "pcaptoparquet_mcp" / "data" / "schema.md"
    assert packaged.is_symlink()


def test_clamp_row_limit() -> None:
    assert clamp_row_limit(None) == 50
    assert clamp_row_limit(0) == 1
    assert clamp_row_limit(1000) == MAX_ROW_LIMIT


def test_path_traversal_rejected(tmp_path: Path) -> None:
    data = tmp_path / "data"
    data.mkdir()
    _write_parquet(data / "ok.parquet")
    outside = tmp_path / "secret.parquet"
    _write_parquet(outside)
    catalog = ParquetCatalog(data)
    with pytest.raises(CatalogError, match="escapes"):
        catalog.resolve_capture("../secret.parquet")
    with pytest.raises(CatalogError, match="relative"):
        catalog.resolve_capture(str(outside))
    with pytest.raises(CatalogError, match="required"):
        catalog.resolve_capture("  ")


def test_list_and_scan_drops_extra_column(tmp_path: Path) -> None:
    cap = _write_parquet(tmp_path / "a.parquet")
    catalog = ParquetCatalog(tmp_path)
    listed = catalog.list_captures()
    assert listed["capture"].to_list() == ["a.parquet"]
    assert listed["num_rows"].to_list() == [5]
    lf = catalog.scan("a.parquet")
    assert "custom_tag" not in lf.collect_schema().names()
    csv = filter_packets(lf, ip_src="10.0.0.1")
    assert "custom_tag" not in csv
    assert "10.0.0.1" in csv
    assert cap.name == "a.parquet"


def test_unsupported_parquet(tmp_path: Path) -> None:
    pl.DataFrame({"foo": [1]}).write_parquet(tmp_path / "other.parquet")
    catalog = ParquetCatalog(tmp_path)
    with pytest.raises(CatalogError, match="unsupported"):
        catalog.scan("other.parquet")


def test_subdir_capture(tmp_path: Path) -> None:
    _write_parquet(tmp_path / "nested" / "b.parquet")
    catalog = ParquetCatalog(tmp_path)
    names = catalog.list_captures()["capture"].to_list()
    assert names == ["nested/b.parquet"]
    lf = catalog.scan("nested")
    assert int(lf.select(pl.len()).collect().item()) == 5


def test_missing_data_root(tmp_path: Path) -> None:
    with pytest.raises(CatalogError, match="not a directory"):
        ParquetCatalog(tmp_path / "missing")


def test_flow_key_and_list_flows() -> None:
    lf = _packet_frame().lazy()
    keyed = with_flow_key(lf).collect()
    assert "udp_8.8.8.8_53_10.0.0.1_53000" in keyed["flow"].to_list()
    csv = list_flows(lf, group_limit=2)
    assert "flow" in csv
    assert csv.count("\n") <= 4


def test_sni_and_app_and_tcp_and_quic() -> None:
    lf = _packet_frame().lazy()
    sni = sni_table(lf)
    assert "example.com" in sni
    msgs = app_messages(lf)
    assert "DNS" in msgs
    assert "www.example.com" in msgs
    syn = tcp_setup(lf)
    assert "TCP" in syn
    quic = quic_initials(lf)
    assert "7" in quic


def test_filter_row_cap_and_summarize() -> None:
    lf = _packet_frame().lazy()
    csv = filter_packets(lf, limit=2)
    # header + 2 rows + trailing newline
    lines = [line for line in csv.strip().splitlines() if line]
    assert len(lines) == 3
    summary = summarize_capture(lf, group_limit=3)
    assert "packet_count,5" in summary
    assert "UDP" in summary


def test_empty_list_captures(tmp_path: Path) -> None:
    catalog = ParquetCatalog(tmp_path)
    df = catalog.list_captures()
    assert df.is_empty()
    assert df.columns == ["capture", "size_bytes", "mtime_utc", "num_rows"]
