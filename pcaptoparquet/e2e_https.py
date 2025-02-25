"""
HTTPS Application module for dpkt.
"""

import struct
from typing import Any, Optional

import dpkt

from pcaptoparquet.e2e_tls_utils import (
    append_if_not_none,
    decode_tls_handshake,
    decode_tls_record,
)


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the RTP protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Decode the application layer as HTTP.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        HTTPS data dpkt object.
    """
    https = None

    if not isinstance(transport, dpkt.tcp.TCP):
        return None

    if len(app) > 0:
        https = app
        setattr(packet, "app_type", "HTTPS")

        # Ugly Hack to skip full TLS decoding...
        try:
            pointer = 0
            while len(https[pointer:]) > 0:

                rr, rr_type, pointer = decode_tls_record(https, pointer)

                if rr_type == 20:  # TLSChangeCipherSpec
                    try:
                        dpkt.ssl.TLSChangeCipherSpec(rr.data)
                        setattr(
                            packet,
                            "app_response",
                            append_if_not_none(
                                getattr(packet, "app_response"), "Change Cipher Spec"
                            ),
                        )
                    except dpkt.ssl.SSL3Exception:
                        pass

                elif rr_type == 21:  # TLSAlert
                    try:
                        dpkt.ssl.TLSAlert(rr.data)
                        setattr(
                            packet,
                            "app_response",
                            append_if_not_none(
                                getattr(packet, "app_response"), "Alert"
                            ),
                        )
                    except dpkt.ssl.SSL3Exception:
                        pass

                elif rr_type == 22:  # TLSHandshake
                    try:
                        (app_session, app_request, app_response, e2e_sni) = (
                            decode_tls_handshake(
                                rr.data,
                                getattr(packet, "app_request"),
                                getattr(packet, "app_response"),
                            )
                        )
                        setattr(packet, "app_session", app_session)
                        setattr(packet, "app_request", app_request)
                        setattr(packet, "app_response", app_response)
                        setattr(packet, "e2e_sni", e2e_sni)
                    except dpkt.ssl.SSL3Exception:
                        pass

                elif rr_type == 23:  # TLSAppData
                    setattr(
                        packet,
                        "app_response",
                        append_if_not_none(
                            getattr(packet, "app_response"), "Application Data"
                        ),
                    )

        except (dpkt.UnpackError, struct.error, AttributeError):
            if (
                getattr(packet, "app_session") is None
                and getattr(packet, "app_request") is None
                and getattr(packet, "app_response") is None
                and getattr(packet, "e2e_sni") is None
            ):
                https = None
    else:
        https = None

    if https is None:
        setattr(packet, "app_type", None)
        setattr(packet, "app_seq", None)
        setattr(packet, "app_request", None)
        setattr(packet, "app_response", None)
        return None

    return bytes(https[pointer:])
