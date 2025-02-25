"""
TLS utils module for pcaptoparquet.
"""

import struct
from typing import Optional

import dpkt


def decode_tls_record(
    https: bytes, pointer: int
) -> tuple[dpkt.ssl.TLSRecord, int, int]:
    """
    Decode the TLS record.

    Throws an UnpackError exception if the request is invalid.
    """
    end = pointer + 5 + struct.unpack("!H", https[pointer + 3 : pointer + 5])[0]
    rr = dpkt.ssl.TLSRecord()
    dpkt.Packet.unpack(rr, https[pointer:])
    header_length = getattr(rr, "__hdr_len__")
    rr.data = https[pointer + header_length : pointer + header_length + rr.length]
    return rr, getattr(rr, "type"), end


def append_if_not_none(current: Optional[str], new: str, symbol: str = " + ") -> str:
    """
    Append a new string to current string if it is not None.
    """
    if current is None:
        current = new
    else:
        current = current + symbol + new
    return current


def decode_tls_handshake(
    rr_data: bytes, app_request: Optional[str], app_response: Optional[str]
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Decode the TLS handshake.

    Throws an UnpackError exception if the request is invalid
    """
    app_session = None
    e2e_sni = None

    record = dpkt.ssl.TLSHandshake(rr_data)
    if isinstance(record.data, dpkt.ssl.TLSClientHello):
        clienthello = record.data
        app_session = append_if_not_none(app_session, clienthello.session_id.hex())
        app_request = append_if_not_none(app_request, "Client Hello")
        for _, extension in enumerate(clienthello.extensions):
            if extension[0] == 0:  # server name
                e2e_sni = extension[1][5:].decode("utf-8")
                sni_str = "Server Name: " + e2e_sni
                app_request = append_if_not_none(app_request, sni_str)
    elif isinstance(record.data, dpkt.ssl.TLSServerHello):
        serverhello = record.data
        app_session = serverhello.session_id.hex()
        app_response = append_if_not_none(app_response, "Server Hello")
    elif isinstance(record.data, dpkt.ssl.TLSAppData):
        app_response = append_if_not_none(app_response, "Application Data")

    return app_session, app_request, app_response, e2e_sni
