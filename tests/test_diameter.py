# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Diameter extension decode must not call bytes() on the AVP list."""

import importlib.util
import os
import unittest
from types import SimpleNamespace
from typing import Any, Callable, Optional

_MODULE_PATH = os.path.join(
    os.path.dirname(__file__), "config", "modules", "e2e_diameter.py"
)


def _load_diameter_decode() -> Callable[[Any, Any, Any], Optional[bytes]]:
    spec = importlib.util.spec_from_file_location("e2e_diameter_test", _MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    decode_fn: Callable[[Any, Any, Any], Optional[bytes]] = module.decode
    return decode_fn


def _diameter_header() -> bytes:
    length = (20).to_bytes(3, "big")
    cmd = (257).to_bytes(3, "big")
    return bytes([1]) + length + bytes([0x80]) + cmd + b"\x00" * 12


class TestDiameterDecode(unittest.TestCase):
    def test_decode_returns_empty_bytes_for_avp_list(self) -> None:
        decode = _load_diameter_decode()
        packet = SimpleNamespace(transport_type="TCP")
        out = decode(packet, None, _diameter_header())
        self.assertEqual(out, b"")
        self.assertEqual(packet.app_type, "Diameter")


if __name__ == "__main__":
    unittest.main()
