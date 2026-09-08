# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Packet-aware MCP companion for pcaptoparquet Parquet collections."""

from .catalog import CatalogError, ParquetCatalog

__all__ = ["CatalogError", "ParquetCatalog"]
