"""
SIP Protocol extension module for dpkt.
"""

from typing import Any, Optional

import dpkt


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the SIP protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Try to decode the application layer as SIP.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        SIP data dpkt object.
    """
    sip = None

    if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        return None

    # SIP...
    try:
        sip = dpkt.sip.Request(app)
        setattr(packet, "app_type", "SIP")

        # Check if "call-id" is present...
        sip_headers = getattr(sip, "headers")
        if "call-id" in sip_headers:
            setattr(packet, "app_session", sip_headers["call-id"])

        # For now to simplify json convertion...
        setattr(packet, "app_request", repr(sip))

    except dpkt.UnpackError:
        # do nothing...
        sip = None

    if not sip:
        try:
            sip = dpkt.sip.Response(app)
            setattr(packet, "app_type", "SIP")

            # Check if "call-id" is present...
            sip_headers = getattr(sip, "headers")
            if "call-id" in sip_headers:
                setattr(packet, "app_session", sip_headers["call-id"])

            # For now to simplify json convertion...
            setattr(packet, "app_response", repr(sip))

        except dpkt.UnpackError:
            # do nothing...
            sip = None

    if sip is None:
        setattr(packet, "app_type", None)
        setattr(packet, "app_seq", None)
        setattr(packet, "app_request", None)
        setattr(packet, "app_response", None)
        return None

    return bytes(getattr(sip, "data")) if sip else None
