"""
HTTP Application module for dpkt.
"""

from io import BytesIO
from typing import Any, Optional

import dpkt


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the RTP protocol.
    """
    return {}


def decode_http_request(
    app: bytes,
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[bytes]]:
    """
    Decode the HTTP Request.

    Throws an UnpackError exception if the request is invalid.
    """
    # Ugly Hack to skip HTTP body decoding...

    http_methods = (
        "GET",
        "PUT",
        "ICY",
        "COPY",
        "HEAD",
        "LOCK",
        "MOVE",
        "POLL",
        "POST",
        "BCOPY",
        "BMOVE",
        "MKCOL",
        "TRACE",
        "LABEL",
        "MERGE",
        "DELETE",
        "SEARCH",
        "UNLOCK",
        "REPORT",
        "UPDATE",
        "NOTIFY",
        "BDELETE",
        "CONNECT",
        "OPTIONS",
        "CHECKIN",
        "PROPFIND",
        "CHECKOUT",
        "CCM_POST",
        "SUBSCRIBE",
        "PROPPATCH",
        "BPROPFIND",
        "BPROPPATCH",
        "UNCHECKOUT",
        "MKACTIVITY",
        "MKWORKSPACE",
        "UNSUBSCRIBE",
        "RPC_CONNECT",
        "VERSION-CONTROL",
        "BASELINE-CONTROL",
    )

    http_proto = "HTTP"

    f = BytesIO(app)
    line = f.readline().decode("ascii", "ignore")
    l_ = line.strip().split()
    if len(l_) < 2:
        raise dpkt.UnpackError(f"Invalid request: {line}")

    if l_[0] not in http_methods:
        raise dpkt.UnpackError(f"invalid http method: {l_[0]}")

    if len(l_) != 2 and not l_[2].startswith(http_proto):
        raise dpkt.UnpackError(f"invalid http version: {l_[2]}")

    http_req = dpkt.http.Request()
    if len(l_) == 2:
        # HTTP/0.9 does not specify a version
        # in the request line
        http_req.version = "0.9"
    else:
        http_req.version = l_[2][len(http_proto) + 1 :]
        http_req.method = l_[0]
        http_req.uri = l_[1]

    msg = dpkt.http.Message(f.read(), False)
    http_req.headers = msg.headers
    http_req.body = msg.body
    http_req.data = msg.data
    app_request = str(http_req).encode("unicode_escape").decode("utf-8")
    app_response = None
    app_type = "HTTP"
    http = http_req

    return app_type, app_request, app_response, http.data


def decode_http_response(
    app: bytes,
) -> tuple[Optional[str], Optional[str], Optional[str], Optional[bytes]]:
    """
    Decode the HTTP Response.

    Throws an UnpackError exception if the request is invalid.
    """
    # Ugly Hack to skip HTTP body decoding...
    http_proto = "HTTP"

    app_request = None
    http_res = dpkt.http.Response()
    f = BytesIO(app)
    byteline = f.readline()
    line = byteline.decode("ascii", "ignore")
    l_ = byteline.strip().decode("ascii", "ignore").split(None, 2)
    if len(l_) < 2 or not l_[0].startswith(http_proto) or not l_[1].isdigit():
        raise dpkt.UnpackError(f"invalid response: {line}")

    http_res.version = l_[0][len(http_proto) + 1 :]
    http_res.status = l_[1]
    http_res.reason = l_[2] if len(l_) > 2 else ""
    msg = dpkt.http.Message(f.read(), False)
    http_res.headers = msg.headers
    http_res.body = msg.body
    http_res.data = msg.data
    app_request = None
    app_response = str(http_res).encode("unicode_escape").decode("utf-8")
    app_type = "HTTP"
    http = http_res

    return app_type, app_request, app_response, http.data


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Decode the application layer as DNS.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        HTTP data dpkt object.
    """
    if not isinstance(transport, dpkt.tcp.TCP):
        return None

    try:
        (app_type, app_request, app_response, app_data) = decode_http_request(app)
        setattr(packet, "app_type", app_type)
        setattr(packet, "app_request", app_request)
        setattr(packet, "app_response", app_response)
    except dpkt.UnpackError:
        setattr(packet, "app_type", None)

    if getattr(packet, "app_type") is None:
        try:
            (app_type, app_request, app_response, app_data) = decode_http_response(app)
            setattr(packet, "app_type", app_type)
            setattr(packet, "app_request", app_request)
            setattr(packet, "app_response", app_response)
        except dpkt.UnpackError:
            setattr(packet, "app_type", None)

    if getattr(packet, "app_type") is None:
        setattr(packet, "app_type", None)
        setattr(packet, "app_seq", None)
        setattr(packet, "app_request", None)
        setattr(packet, "app_response", None)
        return None

    return app_data
