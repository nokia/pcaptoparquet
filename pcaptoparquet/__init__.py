# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""fast, simple pcap converter."""
from __future__ import absolute_import, division

import importlib.metadata

from .e2e_config import E2EConfig
from .e2e_pcap import E2EPcap

try:
    __version__ = importlib.metadata.version("pcaptoparquet")
except KeyError:
    __version__ = "unknown"

try:
    __author__ = importlib.metadata.metadata("pcaptoparquet")["Author"]
except KeyError:
    __author__ = "unknown"

try:
    __email__ = importlib.metadata.metadata("pcaptoparquet")["Author-email"]
except KeyError:
    __email__ = "unknown"


__license__ = "BSD-3-Clause"


__all__ = ["E2EConfig", "E2EPcap"]
