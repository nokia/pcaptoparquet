# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Confine a Parquet directory and open lazy scans for one capture path."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import polars as pl

from pcaptoparquet.e2e_packet import E2EPacket

CORE_COLUMNS = E2EPacket.prefix_columns()
PACKET_COLUMNS = E2EPacket.parquet_columns()
MAX_EXTRA_COLUMNS = 16
PREFERRED_EXTRA_COLUMNS = ("filename", "path")

_LOG = logging.getLogger("pcaptoparquet_mcp")


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
                # Polars COUNT/len on a parquet scan uses file metadata, not page decode.
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
        """Lazy-scan Parquet; keep packet columns plus a few extra tags."""
        paths = self.parquet_paths(capture)
        lf = pl.scan_parquet(
            [str(p) for p in paths],
            missing_columns="insert",
        )
        schema = lf.collect_schema()
        names = schema.names()
        missing = [col for col in CORE_COLUMNS if col not in names]
        if missing:
            raise CatalogError(
                "unsupported Parquet (missing "
                + ", ".join(missing)
                + "); expected a pcaptoparquet packet table"
            )
        keep = [col for col in PACKET_COLUMNS if col in names]
        extras = [col for col in names if col not in PACKET_COLUMNS]
        usable: list[str] = []
        dropped: list[str] = []
        for col in extras:
            if _skip_extra_dtype(schema[col]):
                dropped.append(col)
                continue
            usable.append(col)
        preferred = [col for col in PREFERRED_EXTRA_COLUMNS if col in usable]
        rest = [col for col in usable if col not in preferred]
        chosen = (preferred + rest)[:MAX_EXTRA_COLUMNS]
        overflow = preferred + rest
        if len(overflow) > MAX_EXTRA_COLUMNS:
            dropped.extend(overflow[MAX_EXTRA_COLUMNS:])
        if dropped:
            _LOG.info(
                "dropped %s extra column(s) on scan: %s",
                len(dropped),
                ", ".join(dropped),
            )
        return lf.select(keep + chosen)


def _skip_extra_dtype(dtype: pl.DataType) -> bool:
    """Skip nested, list, and binary extras so payloads stay off the prompt."""
    if dtype == pl.Binary or dtype == pl.Object:
        return True
    is_nested = getattr(dtype, "is_nested", None)
    if callable(is_nested) and is_nested():
        return True
    return False
