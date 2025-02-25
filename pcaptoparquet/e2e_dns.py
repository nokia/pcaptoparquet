# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause
"""
DNS Application module for dpkt.
"""
from typing import Any, Optional

import dpkt


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the DNS protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Decode the application layer as DNS.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        DNS data dpkt object.
    """

    if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        return None

    try:
        dns = dpkt.dns.DNS(app)
        setattr(packet, "app_type", "DNS")
        setattr(packet, "app_session", getattr(dns, "id"))
        setattr(packet, "app_seq", None)
        # For now to simplify json convertion...
        setattr(packet, "app_request", str(getattr(dns, "qd")))
        setattr(packet, "app_response", str(getattr(dns, "an")))

    except dpkt.UnpackError:
        # do nothing...
        dns = None

    if dns is None:
        setattr(packet, "app_type", None)
        setattr(packet, "app_seq", None)
        setattr(packet, "app_request", None)
        setattr(packet, "app_response", None)
        return None

    return bytes(getattr(dns, "data")) if dns else None
