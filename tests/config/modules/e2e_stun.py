"""
STUN Protocol extension module for dpkt.
"""

from typing import Any, Optional

import dpkt


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the STUN protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Try to decode the application layer as STUN.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        STUN data dpkt object.
    """
    stun = None

    if not isinstance(transport, (dpkt.tcp.TCP, dpkt.udp.UDP)):
        return None

    # STUN...
    try:
        stun = dpkt.stun.STUN(app)
        setattr(packet, "app_type", "STUN")
        stun_data = getattr(stun, "data")
        # self.app_seq = stun.seq
        if getattr(stun, "type") in (
            dpkt.stun.BINDING_REQUEST,
            dpkt.stun.BINDING_RESPONSE,
            dpkt.stun.BINDING_ERROR_RESPONSE,
            dpkt.stun.SHARED_SECRET_REQUEST,
            dpkt.stun.SHARED_SECRET_RESPONSE,
            dpkt.stun.SHARED_SECRET_ERROR_RESPONSE,
        ):
            setattr(packet, "app_session", str(getattr(stun, "xid")))
            stun_type = getattr(stun, "type")
            if stun_type in (
                dpkt.stun.BINDING_REQUEST,
                dpkt.stun.SHARED_SECRET_REQUEST,
            ):
                setattr(
                    packet, "app_request", str(dpkt.stun.parse_attrs(stun_data))
                )  # For now to simplify json convertion...
            else:
                setattr(
                    packet, "app_response", str(dpkt.stun.parse_attrs(stun_data))
                )  # For now to simplify json convertion...
        else:
            stun = None
            stun_data = None

    except dpkt.UnpackError:
        # do nothing...
        stun = None
        stun_data = None

    if stun is None:
        setattr(packet, "app_type", None)
        setattr(packet, "app_seq", None)
        setattr(packet, "app_request", None)
        setattr(packet, "app_response", None)
        return None

    return bytes(stun_data) if stun_data else None
