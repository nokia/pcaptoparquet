# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Process-lifetime LRU of successful run() frames (stdio session)."""

from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass
from typing import Optional, Union

import polars as pl

_LOG = logging.getLogger("pcaptoparquet_mcp")

MAX_FRAMES = 8
FrameTable = Union[pl.LazyFrame, pl.DataFrame]


@dataclass
class StoredFrame:
    """One successful run, keyed for frame_id continue."""

    capture: str
    packets_lf: pl.LazyFrame
    current: FrameTable
    joinable: bool


class FrameStore:
    """Keep the last MAX_FRAMES successful runs; evict oldest."""

    def __init__(self, max_frames: int = MAX_FRAMES) -> None:
        self._max = max_frames
        self._order: list[str] = []
        self._items: dict[str, StoredFrame] = {}

    def put(
        self,
        *,
        capture: str,
        packets_lf: pl.LazyFrame,
        current: FrameTable,
        joinable: bool,
    ) -> str:
        """Store a frame and return its id. Evicts the oldest when full."""
        frame_id = secrets.token_hex(8)
        if len(self._order) >= self._max:
            old = self._order.pop(0)
            self._items.pop(old, None)
            _LOG.info("evicted frame %s", old)
        self._order.append(frame_id)
        self._items[frame_id] = StoredFrame(
            capture=capture,
            packets_lf=packets_lf,
            current=current,
            joinable=joinable,
        )
        return frame_id

    def get(self, frame_id: str) -> Optional[StoredFrame]:
        """Return a stored frame, or None if unknown/expired."""
        return self._items.get(frame_id)

    def as_lazy(self, stored: StoredFrame) -> pl.LazyFrame:
        """Continue plans from current (DataFrame → lazy)."""
        if isinstance(stored.current, pl.DataFrame):
            return stored.current.lazy()
        return stored.current
