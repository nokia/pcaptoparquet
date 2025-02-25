"""
PING Application module for dpkt.
"""

from typing import Any, Optional

import dpkt


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the PING protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Decode the application layer as PING.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        PING data dpkt object.
    """
    if isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
        icmp = transport
    else:
        return None

    if isinstance(app, (dpkt.icmp.ICMP.Echo, dpkt.icmp6.ICMP6.Echo)):
        ping = app
    else:
        return None

    # Ugly hack to group ICMP requests and responses
    setattr(packet, "transport_cid", getattr(ping, "id"))
    setattr(packet, "transport_pkn", getattr(ping, "seq"))

    setattr(packet, "app_type", "PING")
    setattr(packet, "app_session", getattr(ping, "id"))
    setattr(packet, "app_seq", getattr(ping, "seq"))

    ip_len = str(getattr(packet, "ip_len"))
    if getattr(icmp, "type") in [0, 129]:
        setattr(packet, "app_response", f"ECHO REPLY {ip_len} bytes.")
    else:
        setattr(packet, "app_request", f"ECHO REQUEST {ip_len} bytes.")

    return bytes(ping.data)
