# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Read-only Polars plans and presets over a pcaptoparquet LazyFrame."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import Any, Callable, Literal, Mapping, Optional, Sequence, TypeVar, cast

import polars as pl

from pcaptoparquet_mcp.catalog import PACKET_COLUMNS

PACKET_ROW_LIMIT = 200
PACKET_PREVIEW_ROWS = 5
AGG_ROW_LIMIT = 5000
DEFAULT_ROW_LIMIT = 50
MAX_ROW_LIMIT = 200
DEFAULT_GROUP_LIMIT = 100
MAX_RESULT_BYTES = 32768
MAX_PLAN_BYTES = 8192
MAX_ERROR_CHARS = 2048
MAX_NAMED_FRAMES = 4
COLLECT_TIMEOUT_S = 30.0
EXPR_DEPTH_MAX = 32

PRESETS = (
    "summarize_capture",
    "list_flows",
    "sni_table",
    "filter_packets",
    "tcp_setup",
    "app_messages",
    "quic_initials",
    "endpoints",
    "conversations",
    "io_stat",
)

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

JoinHow = Literal["inner", "left", "semi", "anti"]
T = TypeVar("T")
PresetResult = tuple[pl.DataFrame, bool]
DEFAULT_IO_STAT_S = 60.0
_ENDPOINT_TYPES = frozenset({"ip", "eth"})
_CONVERSATION_TYPES = frozenset({"ip", "tcp", "udp", "eth"})
_JOIN_HOW: frozenset[str] = frozenset({"inner", "left", "semi", "anti"})
_CMP_OPS = frozenset({"eq", "ne", "gt", "ge", "lt", "le"})
_ARITH_OPS = frozenset({"add", "sub", "mul", "div"})
_AGG = frozenset({"len", "n_unique", "min", "max", "sum", "any", "all"})
_OPS = frozenset(
    {
        "filter",
        "with_columns",
        "select",
        "unique",
        "sort",
        "group_by",
        "join_packets",
        "join",
        "from_frame",
        "head",
    }
)


def frame_to_csv(df: pl.DataFrame) -> str:
    """Render a DataFrame as CSV text."""
    if df.is_empty():
        return "(no rows)\n"
    return df.write_csv()


def error_envelope(message: str, *, plan: Optional[str] = None) -> dict[str, Any]:
    """JSON failure shape for the run tool."""
    text = message if message else "query failed"
    if len(text) > MAX_ERROR_CHARS:
        text = text[:MAX_ERROR_CHARS] + "…"
    envelope: dict[str, Any] = {"error": text}
    if plan is not None:
        envelope["plan"] = plan
    return envelope


def dumps_envelope(payload: Mapping[str, Any]) -> str:
    """Serialize a result envelope to compact JSON text."""
    return json.dumps(payload, separators=(",", ":"))


def clamp_row_limit(limit: Optional[int]) -> int:
    """Clamp a packet-sample limit to [1, MAX_ROW_LIMIT]."""
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


def _limit_groups(lf: pl.LazyFrame, n: int) -> PresetResult:
    """Collect at most n rows; truncated is True when more existed."""
    cap = max(1, n)
    df = lf.head(cap + 1).collect()
    truncated = len(df) > cap
    if truncated:
        df = df.head(cap)
    return df, truncated


def _has(lf: pl.LazyFrame, name: str) -> bool:
    return name in lf.collect_schema().names()


def _require(lf: pl.LazyFrame, *names: str) -> None:
    missing = [name for name in names if not _has(lf, name)]
    if missing:
        raise ValueError("missing columns: " + ", ".join(missing))


def _select_existing(lf: pl.LazyFrame, columns: Sequence[str]) -> pl.LazyFrame:
    names = lf.collect_schema().names()
    present = [col for col in columns if col in names]
    if not present:
        raise ValueError("none of the requested columns are present")
    return lf.select(present)


def _json_cell(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, time):
        return value.isoformat()
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, (bool, int, float, str)):
        return value
    return str(value)


def _rows_payload(df: pl.DataFrame) -> list[list[Any]]:
    rows: list[list[Any]] = []
    for row in df.iter_rows():
        rows.append([_json_cell(cell) for cell in row])
    return rows


def _clip_plan(plan: str) -> str:
    encoded = plan.encode("utf-8")
    if len(encoded) <= MAX_PLAN_BYTES:
        return plan
    clipped = encoded[:MAX_PLAN_BYTES].decode("utf-8", errors="ignore")
    return clipped + "\n…"


def _success_envelope(
    df: pl.DataFrame,
    *,
    truncated: bool,
    plan: Optional[str],
    max_bytes: int,
) -> dict[str, Any]:
    columns = list(df.columns)
    data = _rows_payload(df)
    envelope: dict[str, Any] = {
        "columns": columns,
        "data": data,
        "truncated": truncated,
        "returned_rows": len(data),
    }
    if plan is not None:
        envelope["plan"] = plan
    if not truncated:
        envelope["n_rows"] = len(data)
    encoded = json.dumps(envelope, separators=(",", ":"))
    while len(encoded.encode("utf-8")) > max_bytes and envelope["data"]:
        data = data[:-1]
        envelope["data"] = data
        envelope["returned_rows"] = len(data)
        envelope["truncated"] = True
        envelope.pop("n_rows", None)
        encoded = json.dumps(envelope, separators=(",", ":"))
    return envelope


def _row_cap_for(
    names: Sequence[str],
    steps: Sequence[Mapping[str, Any]],
    packet_preview_rows: int,
) -> int:
    last_head: Optional[int] = None
    if steps:
        last = steps[-1]
        if isinstance(last, dict) and last.get("op") == "head":
            raw_n = last.get("n", last.get("limit"))
            if raw_n is not None:
                last_head = max(1, int(raw_n))
    if "num" in names:
        default = min(PACKET_ROW_LIMIT, max(1, packet_preview_rows))
        if last_head is None:
            return default
        return min(PACKET_ROW_LIMIT, last_head)
    if last_head is None:
        return AGG_ROW_LIMIT
    return min(AGG_ROW_LIMIT, last_head)


def _run_timed(fn: Callable[[], T], timeout_s: float) -> T:
    box: list[T] = []
    errors: list[BaseException] = []
    done = threading.Event()

    def worker() -> None:
        try:
            box.append(fn())
        except BaseException as exc:
            errors.append(exc)
        finally:
            done.set()

    threading.Thread(target=worker, daemon=True, name="pcaptoparquet-collect").start()
    if not done.wait(timeout_s):
        raise TimeoutError("query timed out")
    if errors:
        raise errors[0]
    if not box:
        raise RuntimeError("collect returned no result")
    return box[0]


def _collect(lf: pl.LazyFrame, timeout_s: float) -> pl.DataFrame:
    return _run_timed(lf.collect, timeout_s)


def _as_object(value: Any, *, what: str) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, str):
        if not value.strip():
            return {}
        loaded = json.loads(value)
        if not isinstance(loaded, dict):
            raise ValueError(f"{what} must be a JSON object")
        return loaded
    if isinstance(value, dict):
        return value
    raise ValueError(f"{what} must be a JSON object")


def _args_int(args: Mapping[str, Any], key: str) -> Optional[int]:
    if key not in args or args[key] is None:
        return None
    return int(args[key])


def _args_bool(args: Mapping[str, Any], key: str) -> Optional[bool]:
    if key not in args or args[key] is None:
        return None
    return bool(args[key])


def _args_str(args: Mapping[str, Any], key: str) -> Optional[str]:
    if key not in args or args[key] is None:
        return None
    return str(args[key])


def _args_dt(args: Mapping[str, Any], key: str) -> Optional[datetime]:
    raw = args.get(key)
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw
    text = str(raw).replace("Z", "+00:00")
    return datetime.fromisoformat(text)


def _args_float(args: Mapping[str, Any], key: str) -> Optional[float]:
    if key not in args or args[key] is None:
        return None
    return float(args[key])


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


def _append_row(
    sections: list[str],
    keys: list[Optional[str]],
    values: list[str],
    section: str,
    key: Optional[str],
    value: str,
) -> None:
    sections.append(section)
    keys.append(key)
    values.append(value)


def _preset_summarize(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    n = clamp_group_limit(_args_int(args, "group_limit"))
    sections: list[str] = []
    keys: list[Optional[str]] = []
    values: list[str] = []
    stats_exprs: list[pl.Expr] = [pl.len().alias("packet_count")]
    if _has(lf, "utc_date_time"):
        stats_exprs.extend(
            [
                pl.col("utc_date_time").min().alias("tmin"),
                pl.col("utc_date_time").max().alias("tmax"),
            ]
        )
    if _has(lf, "ip_len"):
        stats_exprs.append(pl.col("ip_len").sum().alias("bytes"))
    if _has(lf, "ip_src"):
        stats_exprs.append(pl.col("ip_src").n_unique().alias("ip_src_n"))
    if _has(lf, "ip_dst"):
        stats_exprs.append(pl.col("ip_dst").n_unique().alias("ip_dst_n"))
    stats = lf.select(stats_exprs).collect()
    row = stats.row(0, named=True)
    total = int(row["packet_count"])
    _append_row(sections, keys, values, "packet_count", None, str(total))
    tmin = row.get("tmin")
    tmax = row.get("tmax")
    if total > 0 and tmin is not None and tmax is not None:
        _append_row(sections, keys, values, "time", "tmin", str(tmin))
        _append_row(sections, keys, values, "time", "tmax", str(tmax))
        if isinstance(tmin, datetime) and isinstance(tmax, datetime):
            duration_s = (tmax - tmin).total_seconds()
            _append_row(sections, keys, values, "duration_s", None, str(duration_s))
            if duration_s > 0:
                _append_row(
                    sections, keys, values, "pps", None, str(total / duration_s)
                )
    if "bytes" in row and row["bytes"] is not None:
        _append_row(sections, keys, values, "bytes", None, str(row["bytes"]))
    if "ip_src_n" in row and row["ip_src_n"] is not None:
        _append_row(sections, keys, values, "ip_src_n", None, str(row["ip_src_n"]))
    if "ip_dst_n" in row and row["ip_dst_n"] is not None:
        _append_row(sections, keys, values, "ip_dst_n", None, str(row["ip_dst_n"]))
    truncated = False
    for col in ("transport_type", "app_type", "tunnel", "ip_src", "ip_dst"):
        if not _has(lf, col):
            continue
        mix, mix_trunc = _limit_groups(
            lf.group_by(col).len().sort("len", descending=True), n
        )
        truncated = truncated or mix_trunc
        for mix_row in mix.iter_rows(named=True):
            key = None if mix_row[col] is None else str(mix_row[col])
            _append_row(sections, keys, values, col, key, str(mix_row["len"]))
    return (
        pl.DataFrame({"section": sections, "key": keys, "value": values}),
        truncated,
    )


def _preset_list_flows(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    n = clamp_group_limit(_args_int(args, "group_limit"))
    keyed = with_flow_key(lf)
    return _limit_groups(keyed.group_by("flow").len().sort("len", descending=True), n)


def _filter_predicate(lf: pl.LazyFrame, args: Mapping[str, Any]) -> Optional[pl.Expr]:
    expr: Optional[pl.Expr] = None

    def _and(next_expr: pl.Expr) -> None:
        nonlocal expr
        expr = next_expr if expr is None else (expr & next_expr)

    ip_src = _args_str(args, "ip_src")
    if ip_src is not None:
        _require(lf, "ip_src")
        _and(pl.col("ip_src").cast(pl.Utf8) == ip_src)
    ip_dst = _args_str(args, "ip_dst")
    if ip_dst is not None:
        _require(lf, "ip_dst")
        _and(pl.col("ip_dst").cast(pl.Utf8) == ip_dst)
    src_port = _args_int(args, "transport_src_port")
    if src_port is not None:
        _require(lf, "transport_src_port")
        _and(pl.col("transport_src_port") == src_port)
    dst_port = _args_int(args, "transport_dst_port")
    if dst_port is not None:
        _require(lf, "transport_dst_port")
        _and(pl.col("transport_dst_port") == dst_port)
    app_type = _args_str(args, "app_type")
    if app_type is not None:
        _require(lf, "app_type")
        _and(pl.col("app_type").cast(pl.Utf8) == app_type)
    transport_type = _args_str(args, "transport_type")
    if transport_type is not None:
        _require(lf, "transport_type")
        _and(pl.col("transport_type").cast(pl.Utf8) == transport_type)
    e2e_sni = _args_str(args, "e2e_sni")
    if e2e_sni is not None:
        _require(lf, "e2e_sni")
        _and(pl.col("e2e_sni") == e2e_sni)
    time_from = _args_dt(args, "time_from")
    if time_from is not None:
        _require(lf, "utc_date_time")
        _and(pl.col("utc_date_time") >= time_from)
    time_to = _args_dt(args, "time_to")
    if time_to is not None:
        _require(lf, "utc_date_time")
        _and(pl.col("utc_date_time") <= time_to)
    return expr


def _preset_filter_packets(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    row_limit = clamp_row_limit(_args_int(args, "limit"))
    pred = _filter_predicate(lf, args)
    filtered = lf.filter(pred) if pred is not None else lf
    return _limit_groups(_select_existing(filtered, FILTER_COLUMNS), row_limit)


def _preset_sni_table(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    _require(lf, "e2e_sni")
    n = clamp_group_limit(_args_int(args, "group_limit"))
    return _limit_groups(
        lf.filter(pl.col("e2e_sni").is_not_null() & (pl.col("e2e_sni") != ""))
        .group_by("e2e_sni")
        .len()
        .sort("len", descending=True),
        n,
    )


def _preset_app_messages(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    _require(lf, "app_type", "app_request", "app_response")
    row_limit = clamp_row_limit(_args_int(args, "limit"))
    cols = [
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
    return _limit_groups(
        lf.filter(
            pl.col("app_type").cast(pl.Utf8).is_in(["DNS", "HTTP"])
            & (
                pl.col("app_request").is_not_null()
                | pl.col("app_response").is_not_null()
            )
        ).select(cols),
        row_limit,
    )


def _preset_tcp_setup(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    _require(lf, "transport_type")
    row_limit = clamp_row_limit(_args_int(args, "limit"))
    syn = _args_bool(args, "syn")
    ack = _args_bool(args, "ack")
    rst = _args_bool(args, "rst")
    fin = _args_bool(args, "fin")
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
    return _limit_groups(_select_existing(filtered, FILTER_COLUMNS), row_limit)


def _preset_quic_initials(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    _require(lf, "transport_pkn")
    row_limit = clamp_row_limit(_args_int(args, "limit"))
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
    return _limit_groups(
        lf.filter(pl.col("transport_pkn").is_not_null()).select(cols),
        row_limit,
    )


def _coalesce_join_key(lf: pl.LazyFrame, name: str) -> pl.LazyFrame:
    right = name + "_right"
    if right not in lf.collect_schema().names():
        return lf
    return lf.with_columns(pl.coalesce([name, right]).alias(name)).drop(right)


def _time_aggs(lf: pl.LazyFrame) -> list[pl.Expr]:
    if not _has(lf, "utc_date_time"):
        return []
    return [
        pl.col("utc_date_time").min().alias("tmin"),
        pl.col("utc_date_time").max().alias("tmax"),
    ]


def _preset_endpoints(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    n = clamp_group_limit(_args_int(args, "group_limit"))
    kind = (_args_str(args, "type") or "ip").lower()
    if kind not in _ENDPOINT_TYPES:
        raise ValueError(f"unsupported endpoints type: {kind}")
    if kind == "ip":
        _require(lf, "ip_src", "ip_dst")
        src_col, dst_col = "ip_src", "ip_dst"
    else:
        _require(lf, "eth_src", "eth_dst")
        src_col, dst_col = "eth_src", "eth_dst"
    use_bytes = _has(lf, "ip_len")
    src_aggs: list[pl.Expr] = [pl.len().alias("packets_src")]
    dst_aggs: list[pl.Expr] = [pl.len().alias("packets_dst")]
    if use_bytes:
        src_aggs.append(pl.col("ip_len").sum().alias("bytes_src"))
        dst_aggs.append(pl.col("ip_len").sum().alias("bytes_dst"))
    src = (
        lf.filter(pl.col(src_col).is_not_null())
        .group_by(pl.col(src_col).cast(pl.Utf8).alias("address"))
        .agg(src_aggs)
    )
    dst = (
        lf.filter(pl.col(dst_col).is_not_null())
        .group_by(pl.col(dst_col).cast(pl.Utf8).alias("address"))
        .agg(dst_aggs)
    )
    joined = _coalesce_join_key(src.join(dst, on="address", how="full"), "address")
    fills = [
        pl.col("packets_src").fill_null(0),
        pl.col("packets_dst").fill_null(0),
    ]
    if use_bytes:
        fills.extend(
            [
                pl.col("bytes_src").fill_null(0),
                pl.col("bytes_dst").fill_null(0),
            ]
        )
    joined = joined.with_columns(fills).with_columns(
        (pl.col("packets_src") + pl.col("packets_dst")).alias("packets")
    )
    out_cols = ["address", "packets_src", "packets_dst", "packets"]
    if use_bytes:
        joined = joined.with_columns(
            (pl.col("bytes_src") + pl.col("bytes_dst")).alias("bytes")
        )
        out_cols.extend(["bytes_src", "bytes_dst", "bytes"])
    return _limit_groups(joined.select(out_cols).sort("packets", descending=True), n)


def _directed_conversation_aggs(lf: pl.LazyFrame) -> list[pl.Expr]:
    aggs: list[pl.Expr] = [pl.len().alias("packets")]
    if _has(lf, "ip_len"):
        aggs.append(pl.col("ip_len").sum().alias("bytes"))
    aggs.extend(_time_aggs(lf))
    return aggs


def _undirected_conversation_aggs(lf: pl.LazyFrame) -> list[pl.Expr]:
    aggs: list[pl.Expr] = [
        pl.when(pl.col("_ab")).then(1).otherwise(0).sum().alias("packets_ab"),
        pl.when(pl.col("_ab")).then(0).otherwise(1).sum().alias("packets_ba"),
        pl.len().alias("packets"),
    ]
    if _has(lf, "ip_len"):
        aggs.extend(
            [
                pl.when(pl.col("_ab"))
                .then(pl.col("ip_len"))
                .otherwise(0)
                .sum()
                .alias("bytes_ab"),
                pl.when(pl.col("_ab"))
                .then(0)
                .otherwise(pl.col("ip_len"))
                .sum()
                .alias("bytes_ba"),
                pl.col("ip_len").sum().alias("bytes"),
            ]
        )
    aggs.extend(_time_aggs(lf))
    return aggs


def _preset_conversations(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    n = clamp_group_limit(_args_int(args, "group_limit"))
    kind = (_args_str(args, "type") or "ip").lower()
    if kind not in _CONVERSATION_TYPES:
        raise ValueError(f"unsupported conversations type: {kind}")
    directed = _args_bool(args, "directed")
    if directed is None:
        directed = False
    frame = lf
    group_keys: list[str]
    if kind in {"tcp", "udp"}:
        _require(
            lf,
            "ip_src",
            "ip_dst",
            "transport_src_port",
            "transport_dst_port",
            "transport_type",
        )
        label = "TCP" if kind == "tcp" else "UDP"
        src = pl.col("ip_src").cast(pl.Utf8)
        dst = pl.col("ip_dst").cast(pl.Utf8)
        sp = pl.col("transport_src_port")
        dp = pl.col("transport_dst_port")
        frame = frame.filter(
            (pl.col("transport_type").cast(pl.Utf8) == label)
            & src.is_not_null()
            & dst.is_not_null()
            & sp.is_not_null()
            & dp.is_not_null()
        )
        if directed:
            group_keys = [
                "ip_src",
                "ip_dst",
                "transport_src_port",
                "transport_dst_port",
            ]
            grouped = frame.group_by(group_keys).agg(_directed_conversation_aggs(frame))
        else:
            swap = (src > dst) | ((src == dst) & (sp > dp))
            frame = frame.with_columns(
                pl.when(swap).then(dst).otherwise(src).alias("endpoint_a"),
                pl.when(swap).then(src).otherwise(dst).alias("endpoint_b"),
                pl.when(swap).then(dp).otherwise(sp).alias("port_a"),
                pl.when(swap).then(sp).otherwise(dp).alias("port_b"),
                (~swap).alias("_ab"),
            )
            group_keys = ["endpoint_a", "endpoint_b", "port_a", "port_b"]
            grouped = frame.group_by(group_keys).agg(
                _undirected_conversation_aggs(frame)
            )
    elif kind == "eth":
        _require(lf, "eth_src", "eth_dst")
        src = pl.col("eth_src").cast(pl.Utf8)
        dst = pl.col("eth_dst").cast(pl.Utf8)
        frame = frame.filter(src.is_not_null() & dst.is_not_null())
        if directed:
            group_keys = ["eth_src", "eth_dst"]
            grouped = frame.group_by(group_keys).agg(_directed_conversation_aggs(frame))
        else:
            swap = src > dst
            frame = frame.with_columns(
                pl.when(swap).then(dst).otherwise(src).alias("eth_a"),
                pl.when(swap).then(src).otherwise(dst).alias("eth_b"),
                (~swap).alias("_ab"),
            )
            group_keys = ["eth_a", "eth_b"]
            grouped = frame.group_by(group_keys).agg(
                _undirected_conversation_aggs(frame)
            )
    else:
        _require(lf, "ip_src", "ip_dst")
        src = pl.col("ip_src").cast(pl.Utf8)
        dst = pl.col("ip_dst").cast(pl.Utf8)
        frame = frame.filter(src.is_not_null() & dst.is_not_null())
        if directed:
            group_keys = ["ip_src", "ip_dst"]
            grouped = frame.group_by(group_keys).agg(_directed_conversation_aggs(frame))
        else:
            swap = src > dst
            frame = frame.with_columns(
                pl.when(swap).then(dst).otherwise(src).alias("endpoint_a"),
                pl.when(swap).then(src).otherwise(dst).alias("endpoint_b"),
                (~swap).alias("_ab"),
            )
            group_keys = ["endpoint_a", "endpoint_b"]
            grouped = frame.group_by(group_keys).agg(
                _undirected_conversation_aggs(frame)
            )
    return _limit_groups(grouped.sort("packets", descending=True), n)


def _preset_io_stat(lf: pl.LazyFrame, args: Mapping[str, Any]) -> PresetResult:
    _require(lf, "utc_date_time")
    n = clamp_group_limit(_args_int(args, "group_limit"))
    raw = _args_float(args, "interval_s")
    interval_s = DEFAULT_IO_STAT_S if raw is None else raw
    if interval_s <= 0:
        raise ValueError("interval_s must be > 0")
    every = timedelta(microseconds=max(1, int(interval_s * 1_000_000)))
    aggs: list[pl.Expr] = [pl.len().alias("packets")]
    if _has(lf, "ip_len"):
        aggs.append(pl.col("ip_len").sum().alias("bytes"))
    return _limit_groups(
        lf.filter(pl.col("utc_date_time").is_not_null())
        .with_columns(pl.col("utc_date_time").dt.truncate(every).alias("bucket"))
        .group_by("bucket")
        .agg(aggs)
        .sort("bucket"),
        n,
    )


_PRESET_FNS: dict[str, Callable[[pl.LazyFrame, Mapping[str, Any]], PresetResult]] = {
    "summarize_capture": _preset_summarize,
    "list_flows": _preset_list_flows,
    "sni_table": _preset_sni_table,
    "filter_packets": _preset_filter_packets,
    "tcp_setup": _preset_tcp_setup,
    "app_messages": _preset_app_messages,
    "quic_initials": _preset_quic_initials,
    "endpoints": _preset_endpoints,
    "conversations": _preset_conversations,
    "io_stat": _preset_io_stat,
}


def _dtype_kind(dtype: pl.DataType) -> str:
    base = dtype.base_type() if hasattr(dtype, "base_type") else dtype
    if base == pl.Duration:
        return "duration"
    if base in (pl.Datetime, pl.Date):
        return "datetime"
    return "other"


def _infer_temporal(node: Any, schema: Optional[Mapping[str, pl.DataType]]) -> str:
    """Classify an expr node as datetime, duration, or other for total_ms."""
    if not isinstance(node, dict) or not node:
        return "other"
    if schema and "col" in node and set(node.keys()) == {"col"}:
        dtype = schema.get(str(node["col"]))
        if dtype is not None:
            return _dtype_kind(dtype)
    if "sub" in node and set(node.keys()) == {"sub"}:
        pair = node["sub"]
        if isinstance(pair, list) and len(pair) == 2:
            left = _infer_temporal(pair[0], schema)
            right = _infer_temporal(pair[1], schema)
            if left == "datetime" and right == "datetime":
                return "duration"
            if left == "duration" and right == "duration":
                return "duration"
            if left == "datetime" or right == "datetime":
                return "datetime"
            if left == "duration" or right == "duration":
                return "duration"
    if "add" in node and set(node.keys()) == {"add"}:
        pair = node["add"]
        if isinstance(pair, list) and len(pair) == 2:
            left = _infer_temporal(pair[0], schema)
            right = _infer_temporal(pair[1], schema)
            if left == "duration" or right == "duration":
                if left == "datetime" or right == "datetime":
                    return "datetime"
                return "duration"
    return "other"


def _eval_expr(
    node: Any,
    *,
    depth: int,
    allowed: set[str],
    schema: Optional[Mapping[str, pl.DataType]] = None,
) -> pl.Expr:
    if depth > EXPR_DEPTH_MAX:
        raise ValueError("expression is too deeply nested")
    if not isinstance(node, dict) or not node:
        raise ValueError("expression must be a JSON object")

    def rec(child: Any) -> pl.Expr:
        return _eval_expr(child, depth=depth + 1, allowed=allowed, schema=schema)

    if "col" in node and set(node.keys()) == {"col"}:
        name = str(node["col"])
        if name not in allowed:
            raise ValueError(f"unknown column: {name}")
        return pl.col(name)
    if "lit" in node and set(node.keys()) == {"lit"}:
        return pl.lit(node["lit"])
    if "not" in node and set(node.keys()) == {"not"}:
        return ~rec(node["not"])
    if "is_null" in node and set(node.keys()) == {"is_null"}:
        return rec(node["is_null"]).is_null()
    if "is_not_null" in node and set(node.keys()) == {"is_not_null"}:
        return rec(node["is_not_null"]).is_not_null()
    if "and" in node and set(node.keys()) == {"and"}:
        items = node["and"]
        if not isinstance(items, list) or len(items) < 2:
            raise ValueError("and requires a list of at least two expressions")
        acc = rec(items[0])
        for item in items[1:]:
            acc = acc & rec(item)
        return acc
    if "or" in node and set(node.keys()) == {"or"}:
        items = node["or"]
        if not isinstance(items, list) or len(items) < 2:
            raise ValueError("or requires a list of at least two expressions")
        acc = rec(items[0])
        for item in items[1:]:
            acc = acc | rec(item)
        return acc
    if "in" in node and set(node.keys()) == {"in"}:
        spec = node["in"]
        if not isinstance(spec, dict):
            raise ValueError("in requires {expr, values}")
        values = spec.get("values")
        if not isinstance(values, list):
            raise ValueError("in.values must be a list")
        inner = spec.get("expr", spec.get("col"))
        if isinstance(inner, str):
            inner_expr = rec({"col": inner})
        else:
            inner_expr = rec(inner)
        return inner_expr.is_in(values)
    if "when" in node:
        if "then" not in node:
            raise ValueError("when requires then")
        otherwise = node.get("otherwise", {"lit": None})
        return (
            pl.when(rec(node["when"])).then(rec(node["then"])).otherwise(rec(otherwise))
        )
    if "total_ms" in node and set(node.keys()) == {"total_ms"}:
        inner_node = node["total_ms"]
        inner = rec(inner_node)
        if _infer_temporal(inner_node, schema) == "datetime":
            return inner.dt.timestamp("ms")
        return inner.dt.total_milliseconds()
    for key in _ARITH_OPS:
        if key in node and set(node.keys()) == {key}:
            pair = node[key]
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError(f"{key} requires [left, right]")
            left = rec(pair[0])
            right = rec(pair[1])
            if key == "add":
                return left + right
            if key == "sub":
                return left - right
            if key == "mul":
                return left * right
            return pl.when(right == 0).then(pl.lit(None)).otherwise(left / right)
    for key in _CMP_OPS:
        if key in node and set(node.keys()) == {key}:
            pair = node[key]
            if not isinstance(pair, list) or len(pair) != 2:
                raise ValueError(f"{key} requires [left, right]")
            left = rec(pair[0])
            right = rec(pair[1])
            if key == "eq":
                return left == right
            if key == "ne":
                return left != right
            if key == "gt":
                return left > right
            if key == "ge":
                return left >= right
            if key == "lt":
                return left < right
            return left <= right
    raise ValueError("unsupported expression: " + ",".join(sorted(node.keys())))


def _frame_schema(lf: pl.LazyFrame) -> tuple[set[str], Mapping[str, pl.DataType]]:
    schema = lf.collect_schema()
    names = schema.names()
    return set(PACKET_COLUMNS) | set(names), schema


def _agg_expr(spec: Mapping[str, Any], *, allowed: set[str]) -> pl.Expr:
    op = spec.get("op")
    if op not in _AGG:
        raise ValueError(f"unsupported aggregation: {op}")
    alias = str(spec["alias"]) if spec.get("alias") else op
    if op == "len":
        return pl.len().alias(alias)
    col = spec.get("col")
    if not col:
        raise ValueError(f"{op} requires col")
    name = str(col)
    if name not in allowed:
        raise ValueError(f"unknown column: {name}")
    expr = pl.col(name)
    if op == "n_unique":
        return expr.n_unique().alias(alias)
    if op == "min":
        return expr.min().alias(alias)
    if op == "max":
        return expr.max().alias(alias)
    if op == "sum":
        return expr.sum().alias(alias)
    if op == "any":
        return expr.any().alias(alias)
    return expr.all().alias(alias)


def apply_steps(
    lf: pl.LazyFrame,
    steps: Sequence[Mapping[str, Any]],
    packets_lf: pl.LazyFrame,
    *,
    named_frames: Optional[Mapping[str, pl.LazyFrame]] = None,
    named_joinable: Optional[Mapping[str, bool]] = None,
    joinable: bool = False,
) -> tuple[pl.LazyFrame, bool]:
    """Apply plan steps lazily. join_packets uses packets_lf (same capture)."""
    current = lf
    names_map = dict(named_frames or {})
    joinable_map = dict(named_joinable or {})
    for raw in steps:
        if not isinstance(raw, dict):
            raise ValueError("each step must be a JSON object")
        op = raw.get("op")
        if op not in _OPS:
            raise ValueError(f"unsupported op: {op}")
        allowed, schema = _frame_schema(current)
        if op == "filter":
            if "expr" not in raw:
                raise ValueError("filter requires expr")
            current = current.filter(
                _eval_expr(raw["expr"], depth=0, allowed=allowed, schema=schema)
            )
        elif op == "with_columns":
            cols = raw.get("columns")
            if not isinstance(cols, list) or not cols:
                raise ValueError("with_columns requires columns")
            exprs: list[pl.Expr] = []
            for item in cols:
                if (
                    not isinstance(item, dict)
                    or "alias" not in item
                    or "expr" not in item
                ):
                    raise ValueError("with_columns item needs alias and expr")
                exprs.append(
                    _eval_expr(
                        item["expr"], depth=0, allowed=allowed, schema=schema
                    ).alias(str(item["alias"]))
                )
            current = current.with_columns(exprs)
        elif op == "select":
            columns = raw.get("columns")
            if not isinstance(columns, list) or not columns:
                raise ValueError("select requires columns")
            names = [str(col) for col in columns]
            missing = [name for name in names if name not in allowed]
            if missing:
                raise ValueError("unknown column: " + ", ".join(missing))
            current = current.select(names)
        elif op == "unique":
            columns = raw.get("columns")
            if columns:
                names = [str(col) for col in columns]
                missing = [name for name in names if name not in allowed]
                if missing:
                    raise ValueError("unknown column: " + ", ".join(missing))
                current = current.select(names).unique()
            else:
                current = current.unique()
            joinable = True
        elif op == "sort":
            by = raw.get("by", raw.get("columns"))
            if not isinstance(by, list) or not by:
                raise ValueError("sort requires by")
            names = [str(col) for col in by]
            missing = [name for name in names if name not in allowed]
            if missing:
                raise ValueError("unknown column: " + ", ".join(missing))
            descending = raw.get("descending", False)
            current = current.sort(names, descending=descending)
        elif op == "group_by":
            keys = raw.get("keys")
            aggs = raw.get("agg")
            if not isinstance(keys, list) or not keys:
                raise ValueError("group_by requires keys")
            if not isinstance(aggs, list) or not aggs:
                raise ValueError("group_by requires agg")
            key_names = [str(col) for col in keys]
            missing = [name for name in key_names if name not in allowed]
            if missing:
                raise ValueError("unknown column: " + ", ".join(missing))
            current = current.group_by(key_names).agg(
                [_agg_expr(item, allowed=allowed) for item in aggs]
            )
            joinable = True
        elif op == "from_frame":
            fname = str(raw.get("frame", ""))
            if fname not in names_map:
                raise ValueError(f"unknown frame: {fname}")
            current = names_map[fname]
            joinable = joinable_map.get(fname, False)
        elif op == "join":
            fname = str(raw.get("frame", ""))
            if fname not in names_map:
                raise ValueError(f"unknown frame: {fname}")
            how = str(raw.get("how", "inner"))
            if how not in _JOIN_HOW:
                raise ValueError(f"unsupported join how: {how}")
            right = names_map[fname]
            on = raw.get("on")
            left_on = raw.get("left_on")
            right_on = raw.get("right_on")
            join_how = cast(JoinHow, how)
            if isinstance(on, list) and on:
                keys = [str(col) for col in on]
                current = current.join(right, on=keys, how=join_how)
            elif isinstance(left_on, list) and isinstance(right_on, list):
                if not left_on or not right_on:
                    raise ValueError("join requires on or left_on+right_on")
                if len(left_on) != len(right_on):
                    raise ValueError("left_on and right_on must be the same length")
                current = current.join(
                    right,
                    left_on=[str(col) for col in left_on],
                    right_on=[str(col) for col in right_on],
                    how=join_how,
                )
            else:
                raise ValueError("join requires on or left_on+right_on")
            joinable = False
        elif op == "join_packets":
            if not joinable:
                raise ValueError("join_packets requires a preceding group_by or unique")
            on = raw.get("on")
            if not isinstance(on, list) or not on:
                raise ValueError("join_packets requires on")
            keys = [str(col) for col in on]
            if "num" in keys:
                raise ValueError("join_packets must not use num as a join key")
            how = str(raw.get("how", "inner"))
            if how not in _JOIN_HOW:
                raise ValueError(f"unsupported join how: {how}")
            left_names = set(packets_lf.collect_schema().names())
            right_names = set(current.collect_schema().names())
            for key in keys:
                if key not in left_names or key not in right_names:
                    raise ValueError(f"join key not in both frames: {key}")
            current = packets_lf.join(current, on=keys, how=cast(JoinHow, how))
            joinable = False
        else:
            n = raw.get("n", raw.get("limit"))
            if n is None:
                raise ValueError("head requires n")
            current = current.head(max(1, int(n)))
    return current, joinable


def _named_frames(
    source: pl.LazyFrame,
    spec: Mapping[str, Any],
    packets_lf: pl.LazyFrame,
) -> tuple[dict[str, pl.LazyFrame], dict[str, bool]]:
    raw_frames = spec.get("frames")
    if raw_frames is None:
        return {}, {}
    if not isinstance(raw_frames, dict):
        raise ValueError("plan.frames must be a JSON object")
    if len(raw_frames) > MAX_NAMED_FRAMES:
        raise ValueError(f"at most {MAX_NAMED_FRAMES} named frames")
    named: dict[str, pl.LazyFrame] = {}
    joinable: dict[str, bool] = {}
    for fname, fspec in raw_frames.items():
        if not isinstance(fspec, dict):
            raise ValueError("each named frame must be a JSON object")
        if "frames" in fspec:
            raise ValueError("nested frames are not allowed")
        fsteps = fspec.get("steps")
        if not isinstance(fsteps, list):
            raise ValueError("named frame steps must be a list")
        named[str(fname)], joinable[str(fname)] = apply_steps(
            source, fsteps, packets_lf
        )
    return named, joinable


@dataclass
class PlanOutcome:
    """execute() envelope plus tables for FrameStore (None on error)."""

    envelope: dict[str, Any]
    result_lf: Optional[pl.LazyFrame]
    collected: Optional[pl.DataFrame]
    joinable: bool
    packet_shaped: bool


def execute(
    lf: pl.LazyFrame,
    *,
    plan: Any = None,
    preset: Optional[str] = None,
    args: Any = None,
    packets_lf: Optional[pl.LazyFrame] = None,
    explain: bool = False,
    timeout_s: float = COLLECT_TIMEOUT_S,
    max_bytes: int = MAX_RESULT_BYTES,
    packet_preview_rows: int = PACKET_PREVIEW_ROWS,
    joinable: bool = False,
) -> dict[str, Any]:
    """Run a JSON plan or named preset; return a JSON envelope."""
    return run_plan(
        lf,
        plan=plan,
        preset=preset,
        args=args,
        packets_lf=packets_lf,
        explain=explain,
        timeout_s=timeout_s,
        max_bytes=max_bytes,
        packet_preview_rows=packet_preview_rows,
        joinable=joinable,
    ).envelope


def run_plan(
    lf: pl.LazyFrame,
    *,
    plan: Any = None,
    preset: Optional[str] = None,
    args: Any = None,
    packets_lf: Optional[pl.LazyFrame] = None,
    explain: bool = False,
    timeout_s: float = COLLECT_TIMEOUT_S,
    max_bytes: int = MAX_RESULT_BYTES,
    packet_preview_rows: int = PACKET_PREVIEW_ROWS,
    joinable: bool = False,
) -> PlanOutcome:
    """Like execute, but also returns tables for session frames."""
    empty = PlanOutcome(
        envelope={},
        result_lf=None,
        collected=None,
        joinable=False,
        packet_shaped=False,
    )
    result_lf: Optional[pl.LazyFrame] = None
    plan_text: Optional[str] = None
    try:
        has_plan = plan is not None and plan != "" and plan != {}
        has_preset = bool(preset)
        if has_plan == has_preset:
            raise ValueError("pass plan or preset, not both")
        parsed_args = _as_object(args, what="args")
        if has_preset:
            name = str(preset)
            if name not in _PRESET_FNS:
                raise ValueError(f"unknown preset: {name}")
            df, truncated = _run_timed(
                lambda: _PRESET_FNS[name](lf, parsed_args), timeout_s
            )
            envelope = _success_envelope(
                df, truncated=truncated, plan=None, max_bytes=max_bytes
            )
            packet_shaped = "num" in df.columns
            return PlanOutcome(
                envelope=envelope,
                result_lf=None,
                collected=df,
                joinable=False,
                packet_shaped=packet_shaped,
            )
        spec = _as_object(plan, what="plan")
        steps = spec.get("steps")
        if not isinstance(steps, list):
            raise ValueError("plan.steps must be a list")
        packets = packets_lf if packets_lf is not None else lf
        named, named_joinable = _named_frames(lf, spec, packets)
        result_lf, result_joinable = apply_steps(
            lf,
            steps,
            packets,
            named_frames=named,
            named_joinable=named_joinable,
            joinable=joinable,
        )
        names = result_lf.collect_schema().names()
        cap = _row_cap_for(names, steps, packet_preview_rows)
        try:
            plan_text = _clip_plan(result_lf.explain(optimized=True))
        except Exception:
            plan_text = None
        success_plan = plan_text if explain else None
        df = _collect(result_lf.head(cap + 1), timeout_s)
        truncated = len(df) > cap
        if truncated:
            df = df.head(cap)
        envelope = _success_envelope(
            df, truncated=truncated, plan=success_plan, max_bytes=max_bytes
        )
        packet_shaped = "num" in names
        stored_current: Optional[pl.LazyFrame]
        stored_df: Optional[pl.DataFrame]
        if packet_shaped:
            stored_current = result_lf
            stored_df = None
        else:
            stored_current = None
            stored_df = df
        return PlanOutcome(
            envelope=envelope,
            result_lf=stored_current,
            collected=stored_df,
            joinable=result_joinable,
            packet_shaped=packet_shaped,
        )
    except TimeoutError:
        explain_text = plan_text
        if explain_text is None and result_lf is not None:
            try:
                explain_text = _clip_plan(result_lf.explain(optimized=True))
            except Exception:
                explain_text = None
        empty.envelope = error_envelope("query timed out", plan=explain_text)
        return empty
    except json.JSONDecodeError as exc:
        empty.envelope = error_envelope(f"invalid JSON: {exc}")
        return empty
    except Exception as exc:
        empty.envelope = error_envelope(str(exc))
        return empty
