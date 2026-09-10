# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Tests for pcaptoparquet_mcp catalog and Polars run plans."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import polars as pl
import pytest

from pcaptoparquet.e2e_packet import E2EPacket
from pcaptoparquet_mcp.catalog import (
    CORE_COLUMNS,
    PACKET_COLUMNS,
    CatalogError,
    ParquetCatalog,
)
from pcaptoparquet_mcp.frames import FrameStore
from pcaptoparquet_mcp.queries import PRESETS, execute
from pcaptoparquet_mcp.resources import load_schema_markdown
from pcaptoparquet_mcp.server import run_capture


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
            "ip_len": [80, 60, 80, 100, 40],
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


def _assert_ok(payload: dict[str, Any]) -> dict[str, Any]:
    assert "error" not in payload, payload
    return payload


def test_schema_md_matches_repo_root() -> None:
    root = Path(__file__).resolve().parents[1] / "schema.md"
    assert load_schema_markdown() == root.read_text(encoding="utf-8")
    packaged = root.parent / "pcaptoparquet_mcp" / "data" / "schema.md"
    assert packaged.is_symlink()
    assert CORE_COLUMNS == E2EPacket.prefix_columns()
    assert PACKET_COLUMNS == E2EPacket.parquet_columns()
    schema = root.read_text(encoding="utf-8")
    for name in PACKET_COLUMNS:
        assert f"**{name}**" in schema


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


def test_list_and_scan_keeps_extra_column(tmp_path: Path) -> None:
    cap = _write_parquet(tmp_path / "a.parquet")
    catalog = ParquetCatalog(tmp_path)
    listed = catalog.list_captures()
    assert listed["capture"].to_list() == ["a.parquet"]
    assert listed["num_rows"].to_list() == [5]
    lf = catalog.scan("a.parquet")
    assert "custom_tag" in lf.collect_schema().names()
    payload = execute(
        lf,
        plan={
            "steps": [
                {
                    "op": "filter",
                    "expr": {"eq": [{"col": "ip_src"}, {"lit": "10.0.0.1"}]},
                },
                {"op": "select", "columns": ["ip_src"]},
            ]
        },
    )
    _assert_ok(payload)
    assert payload["data"][0][0] == "10.0.0.1"
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
    payload = execute(lf, plan={"steps": [{"op": "select", "columns": ["num"]}]})
    _assert_ok(payload)
    assert payload["returned_rows"] == 5


def test_missing_data_root(tmp_path: Path) -> None:
    with pytest.raises(CatalogError, match="not a directory"):
        ParquetCatalog(tmp_path / "missing")


def test_aggregations_are_small() -> None:
    lf = _packet_frame().lazy()
    grouped = _assert_ok(
        execute(
            lf,
            plan={
                "steps": [
                    {
                        "op": "group_by",
                        "keys": ["transport_type"],
                        "agg": [{"op": "len", "alias": "n"}],
                    }
                ]
            },
        )
    )
    assert grouped["truncated"] is False
    assert grouped["returned_rows"] <= 3
    types = {row[0] for row in grouped["data"]}
    assert types == {"UDP", "TCP"}
    distinct = _assert_ok(
        execute(
            lf,
            plan={"steps": [{"op": "unique", "columns": ["e2e_sni"]}]},
        )
    )
    assert distinct["truncated"] is False
    assert distinct["returned_rows"] <= 3


def test_packet_head_truncated() -> None:
    rows = []
    base = _packet_frame()
    for i in range(50):
        extra = base.with_columns(pl.col("num") + i * 5)
        rows.append(extra)
    lf = pl.concat(rows).lazy()
    payload = execute(lf, plan={"steps": []})
    assert "error" not in payload
    assert payload["truncated"] is True
    assert payload["returned_rows"] == 5
    assert "n_rows" not in payload
    headed = execute(lf, plan={"steps": [{"op": "head", "n": 10}]})
    assert headed["returned_rows"] == 10
    assert "error" not in headed


def test_presets_sni_and_tcp() -> None:
    lf = _packet_frame().lazy()
    sni = _assert_ok(execute(lf, preset="sni_table"))
    assert "example.com" in [row[0] for row in sni["data"]]
    syn = _assert_ok(execute(lf, preset="tcp_setup"))
    assert syn["returned_rows"] >= 1
    mix = _assert_ok(execute(lf, preset="summarize_capture"))
    sections = [row[0] for row in mix["data"]]
    assert "packet_count" in sections
    assert "duration_s" in sections
    assert "ip_src_n" in sections
    assert "bytes" in sections
    flows = _assert_ok(execute(lf, preset="list_flows"))
    assert flows["returned_rows"] >= 1
    assert mix["truncated"] is False


def test_join_packets_after_group_by() -> None:
    lf = _packet_frame().lazy()
    payload = _assert_ok(
        execute(
            lf,
            packets_lf=lf,
            plan={
                "steps": [
                    {
                        "op": "group_by",
                        "keys": ["ip_src", "ip_dst"],
                        "agg": [{"op": "len", "alias": "n"}],
                    },
                    {
                        "op": "join_packets",
                        "on": ["ip_src", "ip_dst"],
                        "how": "inner",
                    },
                    {"op": "select", "columns": ["ip_src", "ip_dst", "n"]},
                    {"op": "unique", "columns": ["ip_src", "ip_dst", "n"]},
                ]
            },
        )
    )
    assert payload["truncated"] is False
    pairs = {(row[0], row[1]) for row in payload["data"]}
    assert ("10.0.0.1", "8.8.8.8") in pairs
    assert "num" not in payload["columns"]
    assert payload["returned_rows"] == 4
    assert payload["n_rows"] == 4


def test_join_packets_rejected_without_group() -> None:
    lf = _packet_frame().lazy()
    payload = execute(
        lf,
        packets_lf=lf,
        plan={
            "steps": [
                {
                    "op": "join_packets",
                    "on": ["ip_src", "ip_dst"],
                    "how": "inner",
                }
            ]
        },
    )
    assert "error" in payload
    on_num = execute(
        lf,
        packets_lf=lf,
        plan={
            "steps": [
                {
                    "op": "unique",
                    "columns": ["num", "ip_src"],
                },
                {"op": "join_packets", "on": ["num"], "how": "inner"},
            ]
        },
    )
    assert "error" in on_num


def test_plan_xor_preset() -> None:
    lf = _packet_frame().lazy()
    assert "error" in execute(lf)
    assert "error" in execute(lf, plan={"steps": []}, preset="sni_table")


def test_endpoints_src_and_dst() -> None:
    lf = _packet_frame().lazy()
    payload = _assert_ok(execute(lf, preset="endpoints"))
    cols = payload["columns"]
    addr_i = cols.index("address")
    src_i = cols.index("packets_src")
    dst_i = cols.index("packets_dst")
    by_addr = {row[addr_i]: row for row in payload["data"]}
    assert by_addr["10.0.0.1"][src_i] == 3
    assert by_addr["10.0.0.1"][dst_i] == 1
    assert "bytes" in cols
    assert payload["truncated"] is False


def test_conversations_undirected_pair() -> None:
    lf = _packet_frame().lazy()
    payload = _assert_ok(execute(lf, preset="conversations"))
    cols = payload["columns"]
    a_i = cols.index("endpoint_a")
    b_i = cols.index("endpoint_b")
    ab_i = cols.index("packets_ab")
    ba_i = cols.index("packets_ba")
    n_i = cols.index("packets")
    pair = None
    for row in payload["data"]:
        ends = {row[a_i], row[b_i]}
        if ends == {"10.0.0.1", "8.8.8.8"}:
            pair = row
            break
    assert pair is not None
    assert pair[ab_i] + pair[ba_i] == pair[n_i]
    assert pair[n_i] == 2
    unknown = execute(lf, preset="conversations", args={"type": "sctp"})
    assert "error" in unknown


def test_io_stat_hourly_buckets() -> None:
    lf = _packet_frame().lazy()
    payload = _assert_ok(execute(lf, preset="io_stat", args={"interval_s": 3600}))
    assert payload["truncated"] is False
    assert payload["returned_rows"] == 5
    buckets = [row[payload["columns"].index("bucket")] for row in payload["data"]]
    assert buckets == sorted(buckets)
    zero = execute(lf, preset="io_stat", args={"interval_s": 0})
    assert "error" in zero


def test_io_stat_truncates_later_buckets() -> None:
    times = [_utc(2024, 1, 1, 0) + timedelta(seconds=i) for i in range(8)]
    lf = pl.DataFrame(
        {
            "num": list(range(8)),
            "utc_date_time": times,
            "ip_src": ["10.0.0.1"] * 8,
            "ip_dst": ["8.8.8.8"] * 8,
        }
    ).lazy()
    payload = _assert_ok(
        execute(
            lf,
            preset="io_stat",
            args={"interval_s": 1, "group_limit": 3},
        )
    )
    assert payload["truncated"] is True
    assert payload["returned_rows"] == 3
    bucket_i = payload["columns"].index("bucket")
    kept = [row[bucket_i] for row in payload["data"]]
    max_kept = max(kept)
    assert max_kept < times[-1].isoformat()


def test_preset_names() -> None:
    assert "endpoints" in PRESETS
    assert "conversations" in PRESETS
    assert "io_stat" in PRESETS
    assert "ports" not in PRESETS
    assert "app_requests" not in PRESETS


def test_empty_list_captures(tmp_path: Path) -> None:
    catalog = ParquetCatalog(tmp_path)
    df = catalog.list_captures()
    assert df.is_empty()
    assert df.columns == ["capture", "size_bytes", "mtime_utc", "num_rows"]


def test_timeout_does_not_block_next(monkeypatch: pytest.MonkeyPatch) -> None:
    lf = _packet_frame().lazy()

    def _slow(self: pl.LazyFrame) -> pl.DataFrame:
        time.sleep(2.0)
        return pl.DataFrame({"num": [1]})

    monkeypatch.setattr(pl.LazyFrame, "collect", _slow)
    started = time.monotonic()
    first = execute(lf, plan={"steps": []}, timeout_s=0.15)
    second = execute(lf, plan={"steps": []}, timeout_s=0.15)
    elapsed = time.monotonic() - started
    assert "error" in first
    assert "query timed out" in first["error"]
    assert "data" not in first
    assert "frame_id" not in first
    assert "plan" in first
    assert "error" in second
    assert elapsed < 1.5


def test_aggregate_not_preview_capped() -> None:
    lf = pl.DataFrame(
        {
            "num": list(range(10)),
            "ip_src": [f"10.0.0.{i}" for i in range(10)],
            "ip_dst": ["8.8.8.8"] * 10,
            "ip_len": [10] * 10,
        }
    ).lazy()
    payload = _assert_ok(
        execute(
            lf,
            plan={
                "steps": [
                    {
                        "op": "group_by",
                        "keys": ["ip_src"],
                        "agg": [{"op": "len", "alias": "n"}],
                    }
                ]
            },
        )
    )
    assert payload["truncated"] is False
    assert payload["returned_rows"] == 10
    assert payload["n_rows"] == 10
    assert "num" not in payload["columns"]


def test_arithmetic_div_zero_is_null() -> None:
    lf = _packet_frame().lazy()
    payload = _assert_ok(
        execute(
            lf,
            plan={
                "steps": [
                    {
                        "op": "with_columns",
                        "columns": [
                            {
                                "alias": "half",
                                "expr": {"div": [{"col": "ip_len"}, {"lit": 2}]},
                            },
                            {
                                "alias": "zero",
                                "expr": {"div": [{"col": "ip_len"}, {"lit": 0}]},
                            },
                            {
                                "alias": "delta",
                                "expr": {"sub": [{"col": "ip_len"}, {"lit": 40}]},
                            },
                        ],
                    },
                    {"op": "select", "columns": ["ip_len", "half", "zero", "delta"]},
                ]
            },
        )
    )
    cols = payload["columns"]
    zero_i = cols.index("zero")
    half_i = cols.index("half")
    assert payload["returned_rows"] == 5
    assert all(row[zero_i] is None for row in payload["data"])
    assert payload["data"][0][half_i] == 40.0


def test_total_ms_duration_non_negative() -> None:
    lf = _packet_frame().lazy()
    payload = _assert_ok(
        execute(
            lf,
            plan={
                "steps": [
                    {
                        "op": "group_by",
                        "keys": ["transport_type"],
                        "agg": [
                            {"op": "min", "col": "utc_date_time", "alias": "tmin"},
                            {"op": "max", "col": "utc_date_time", "alias": "tmax"},
                        ],
                    },
                    {
                        "op": "with_columns",
                        "columns": [
                            {
                                "alias": "span_ms",
                                "expr": {
                                    "total_ms": {
                                        "sub": [{"col": "tmax"}, {"col": "tmin"}]
                                    }
                                },
                            }
                        ],
                    },
                ]
            },
        )
    )
    span_i = payload["columns"].index("span_ms")
    assert payload["returned_rows"] >= 1
    for row in payload["data"]:
        assert isinstance(row[span_i], int)
        assert row[span_i] >= 0


def test_named_frames_join_bytes_ratio() -> None:
    lf = _packet_frame().lazy()
    payload = _assert_ok(
        execute(
            lf,
            plan={
                "frames": {
                    "by_src": {
                        "steps": [
                            {
                                "op": "group_by",
                                "keys": ["ip_src"],
                                "agg": [
                                    {
                                        "op": "sum",
                                        "col": "ip_len",
                                        "alias": "bytes_src",
                                    }
                                ],
                            }
                        ]
                    },
                    "by_dst": {
                        "steps": [
                            {
                                "op": "group_by",
                                "keys": ["ip_dst"],
                                "agg": [
                                    {
                                        "op": "sum",
                                        "col": "ip_len",
                                        "alias": "bytes_dst",
                                    }
                                ],
                            }
                        ]
                    },
                },
                "steps": [
                    {"op": "from_frame", "frame": "by_src"},
                    {
                        "op": "join",
                        "frame": "by_dst",
                        "left_on": ["ip_src"],
                        "right_on": ["ip_dst"],
                        "how": "left",
                    },
                    {
                        "op": "with_columns",
                        "columns": [
                            {
                                "alias": "bytes_ratio",
                                "expr": {
                                    "div": [
                                        {"col": "bytes_src"},
                                        {"col": "bytes_dst"},
                                    ]
                                },
                            }
                        ],
                    },
                    {"op": "sort", "by": ["bytes_src"], "descending": True},
                    {"op": "head", "n": 5},
                ],
            },
        )
    )
    assert "bytes_ratio" in payload["columns"]
    assert "num" not in payload["columns"]
    assert payload["returned_rows"] >= 1
    assert payload["truncated"] is False


def test_scan_filename_group_by(tmp_path: Path) -> None:
    df = (
        _packet_frame()
        .drop("custom_tag")
        .with_columns(
            pl.Series("filename", ["a.pcap", "a.pcap", "b.pcap", "b.pcap", "b.pcap"])
        )
    )
    df.write_parquet(tmp_path / "bulk.parquet")
    lf = ParquetCatalog(tmp_path).scan("bulk.parquet")
    assert "filename" in lf.collect_schema().names()
    payload = _assert_ok(
        execute(
            lf,
            plan={
                "steps": [
                    {
                        "op": "group_by",
                        "keys": ["filename"],
                        "agg": [{"op": "len", "alias": "n"}],
                    }
                ]
            },
        )
    )
    names = {row[0] for row in payload["data"]}
    assert names == {"a.pcap", "b.pcap"}
    assert payload["returned_rows"] == 2


def test_scan_skips_binary_extra(tmp_path: Path) -> None:
    df = (
        _packet_frame()
        .drop("custom_tag")
        .with_columns(pl.Series("blob", [b"x"] * 5, dtype=pl.Binary))
    )
    df.write_parquet(tmp_path / "bin.parquet")
    names = ParquetCatalog(tmp_path).scan("bin.parquet").collect_schema().names()
    assert "blob" not in names


def test_frame_store_lru() -> None:
    store = FrameStore(max_frames=2)
    lf = _packet_frame().lazy()
    df = pl.DataFrame({"x": [1]})
    first = store.put(capture="a", packets_lf=lf, current=df, joinable=True)
    second = store.put(capture="b", packets_lf=lf, current=df, joinable=False)
    third = store.put(capture="c", packets_lf=lf, current=df, joinable=False)
    assert store.get(first) is None
    assert store.get(second) is not None
    assert store.get(third) is not None


def test_frame_id_continue_does_not_rescan(tmp_path: Path) -> None:
    _write_parquet(tmp_path / "a.parquet", extra=False)
    _write_parquet(tmp_path / "b.parquet", extra=False)
    catalog = ParquetCatalog(tmp_path)
    store = FrameStore()
    scans: list[str] = []
    orig = catalog.scan

    def _scan(capture: str) -> pl.LazyFrame:
        scans.append(capture)
        return orig(capture)

    catalog.scan = _scan  # type: ignore[method-assign]
    grouped = _assert_ok(
        run_capture(
            catalog,
            store,
            capture="a.parquet",
            plan={
                "steps": [
                    {
                        "op": "group_by",
                        "keys": ["transport_type"],
                        "agg": [{"op": "len", "alias": "n"}],
                    }
                ]
            },
        )
    )
    frame_id = grouped["frame_id"]
    assert scans == ["a.parquet"]
    topped = _assert_ok(
        run_capture(
            catalog,
            store,
            capture="a.parquet",
            frame_id=frame_id,
            plan={
                "steps": [
                    {"op": "sort", "by": ["n"], "descending": True},
                    {"op": "head", "n": 1},
                ]
            },
        )
    )
    assert scans == ["a.parquet"]
    assert topped["returned_rows"] == 1
    assert "n" in topped["columns"]
    wrong = run_capture(
        catalog,
        store,
        capture="b.parquet",
        frame_id=frame_id,
        plan={"steps": [{"op": "head", "n": 1}]},
    )
    assert "error" in wrong
    missing = run_capture(
        catalog,
        store,
        capture="a.parquet",
        frame_id="deadbeefdeadbeef",
        plan={"steps": [{"op": "head", "n": 1}]},
    )
    assert "error" in missing
