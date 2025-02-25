"""
RTP Protocol extension module for dpkt.
"""

from typing import Any, Optional

import dpkt


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the RTP protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Try to decode the application layer as RTP.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        RTP data dpkt object.
    """
    rtp = None

    if not isinstance(transport, dpkt.udp.UDP):
        return None

    try:
        rtp = dpkt.rtp.RTP(app)
        if getattr(rtp, "version") == 2 and getattr(rtp, "m") == 0:
            setattr(packet, "app_type", "RTP")
            setattr(packet, "app_session", getattr(rtp, "ssrc"))
            setattr(packet, "app_seq", getattr(rtp, "seq"))
            if getattr(rtp, "pt") < 96:
                # For now to simplify json convertion...
                setattr(packet, "app_request", str(getattr(rtp, "pt")))
            else:
                # For now to simplify json convertion...
                setattr(
                    packet, "app_request", "DynamicRTP-Type-" + str(getattr(rtp, "pt"))
                )
        else:
            rtp = None

    except dpkt.UnpackError:
        # do nothing...
        rtp = None

    if rtp is None:
        setattr(packet, "app_type", None)
        setattr(packet, "app_seq", None)
        setattr(packet, "app_request", None)
        setattr(packet, "app_response", None)
        return None

    return bytes(getattr(rtp, "data")) if rtp else None
