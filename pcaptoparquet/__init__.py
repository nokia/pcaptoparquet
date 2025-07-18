# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""fast, simple pcap converter."""
from __future__ import absolute_import, division

import importlib.metadata

from .e2e_cli import E2ECli
from .e2e_config import E2EConfig
from .e2e_pcap import E2EPcap

PACKAGE_NAME = "pcaptoparquet"

try:
    __version__ = importlib.metadata.version(PACKAGE_NAME)
except KeyError:
    __version__ = "unknown"

try:
    if "Author" in importlib.metadata.metadata(PACKAGE_NAME):
        __author__ = importlib.metadata.metadata(PACKAGE_NAME)["Author"]
    else:
        __author__ = "Pablo Rojo"
except KeyError:
    __author__ = "unknown"

try:
    if "Author-email" in importlib.metadata.metadata(PACKAGE_NAME):
        __email__ = importlib.metadata.metadata(PACKAGE_NAME)["Author-email"]
    else:
        __email__ = "pablo.rojo@nokia.com"
except KeyError:
    __email__ = "unknown"


__license__ = "BSD-3-Clause"


__all__ = ["E2EConfig", "E2EPcap", "E2ECli"]
