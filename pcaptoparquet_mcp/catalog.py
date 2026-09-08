# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Confine a Parquet directory and open lazy scans for one capture path."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import polars as pl

CORE_COLUMNS = ("num", "utc_date_time")
PACKET_COLUMNS = CORE_COLUMNS + (
    "eth_src",
    "eth_dst",
    "eth_vlan_tags",
    "eth_mpls_labels",
    "tunnel",
    "ip_version",
    "ip_src",
    "ip_dst",
    "ip_dscp",
    "ip_ecn",
    "ip_id",
    "ip_ttl",
    "ip_len",
    "ip_frag",
    "esp_spi",
    "esp_seq",
    "transport_type",
    "transport_header_len",
    "transport_options_len",
    "transport_data_len",
    "transport_capture_len",
    "transport_src_port",
    "transport_dst_port",
    "transport_fin_flag",
    "transport_syn_flag",
    "transport_ack_flag",
    "transport_rst_flag",
    "transport_push_flag",
    "transport_urg_flag",
    "transport_ece_flag",
    "transport_cwr_flag",
    "transport_ns_flag",
    "transport_seq",
    "transport_ack",
    "transport_win",
    "transport_mss",
    "transport_wscale",
    "transport_sackok",
    "transport_sack_1_from",
    "transport_sack_1_to",
    "transport_sack_2_from",
    "transport_sack_2_to",
    "transport_sack_3_from",
    "transport_sack_3_to",
    "transport_tsval",
    "transport_tsecr",
    "transport_spin",
    "transport_cid",
    "transport_pkn",
    "e2e_sni",
    "app_type",
    "app_session",
    "app_seq",
    "app_request",
    "app_response",
)


class CatalogError(ValueError):
    """Invalid data root or capture path."""


class ParquetCatalog:
    """Read-only index of ``*.parquet`` files under a resolved directory."""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        if not self.root.is_dir():
            raise CatalogError(
                f"Parquet directory is missing or not a directory: {self.root}"
            )
        if not os.access(self.root, os.R_OK):
            raise CatalogError(f"Parquet directory is not readable: {self.root}")

    def resolve_capture(self, capture: str) -> Path:
        """Resolve a relative capture file or subdirectory inside the root."""
        if capture is None or not str(capture).strip():
            raise CatalogError("capture is required")
        cap = str(capture).strip()
        cap_path = Path(cap)
        if cap_path.is_absolute():
            raise CatalogError("capture must be a relative path")
        if cap.startswith("/") or cap.startswith("\\"):
            raise CatalogError("capture must be a relative path")
        candidate = (self.root / cap).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise CatalogError("capture escapes the Parquet directory") from exc
        return candidate

    def parquet_paths(self, capture: str) -> list[Path]:
        """List Parquet files for a capture file or subdirectory."""
        target = self.resolve_capture(capture)
        if target.is_file():
            if target.suffix.lower() != ".parquet":
                raise CatalogError(f"not a Parquet file: {capture}")
            return [target]
        if target.is_dir():
            paths = sorted(p for p in target.rglob("*.parquet") if p.is_file())
            if not paths:
                raise CatalogError(f"no Parquet files under capture: {capture}")
            return paths
        raise CatalogError(f"capture not found: {capture}")

    def list_captures(self) -> pl.DataFrame:
        """Relative paths, size, mtime, and metadata row counts."""
        files = sorted(p for p in self.root.rglob("*.parquet") if p.is_file())
        rows: list[dict[str, Any]] = []
        for path in files:
            rel = path.relative_to(self.root).as_posix()
            stat = path.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            try:
                num_rows = int(pl.scan_parquet(path).select(pl.len()).collect().item())
            except Exception:
                num_rows = None
            rows.append(
                {
                    "capture": rel,
                    "size_bytes": int(stat.st_size),
                    "mtime_utc": mtime.isoformat(),
                    "num_rows": num_rows,
                }
            )
        if not rows:
            return pl.DataFrame(
                schema={
                    "capture": pl.Utf8,
                    "size_bytes": pl.Int64,
                    "mtime_utc": pl.Utf8,
                    "num_rows": pl.Int64,
                }
            )
        return pl.DataFrame(rows)

    def scan(self, capture: str) -> pl.LazyFrame:
        """Lazy-scan Parquet for one capture; extra columns are ignored."""
        paths = self.parquet_paths(capture)
        lf = pl.scan_parquet(
            [str(p) for p in paths],
            extra_columns="ignore",
            missing_columns="insert",
        )
        names = lf.collect_schema().names()
        missing = [col for col in CORE_COLUMNS if col not in names]
        if missing:
            raise CatalogError(
                "unsupported Parquet (missing "
                + ", ".join(missing)
                + "); expected a pcaptoparquet packet table"
            )
        keep = [col for col in PACKET_COLUMNS if col in names]
        return lf.select(keep)
