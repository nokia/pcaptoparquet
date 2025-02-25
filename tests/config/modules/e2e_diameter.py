"""Diameter."""

import struct
from typing import Any, Optional

import dpkt
from dpkt.compat import compat_ord

# Diameter Base Protocol - RFC 3588
# http://tools.ietf.org/html/rfc3588

# Request/Answer Command Codes
ABORT_SESSION = 274
ACCOUNTING = 271
CAPABILITIES_EXCHANGE = 257
DEVICE_WATCHDOG = 280
DISCONNECT_PEER = 282
RE_AUTH = 258
SESSION_TERMINATION = 275

AA_MOBILE_NODE = 260  # DIAMETER MOBILE IPV4 - RFC 4004
HOME_AGENT_MIP = 262  # DIAMETER MOBILE IPV4 - RFC 4004
AA = 265  # DIAMETER NAS APPLICATION - RFC 7155
DIAMETER_EAP = 268  # DIAMETER EAP APPLICATION - RFC 4072
CREDIT_CONTROL = 272  # DIAMETER CREDIT-CONTROL APPLICATION - RFC 8506
USER_AUTHORIZATION = 283  # DIAMETER SIP APPLICATION - RFC 4740
SERVER_ASSIGNMENT = 284  # DIAMETER SIP APPLICATION - RFC 4740
LOCATION_INFO = 285  # DIAMETER SIP APPLICATION - RFC 4740
MULTIMEDIA_AUTH = 286  # DIAMETER SIP APPLICATION - RFC 4740
REGISTRATION_TERMINATION = 287  # DIAMETER SIP APPLICATION - RFC 4740
PUSH_PROFILE = 288  # DIAMETER SIP APPLICATION - RFC 4740
USER_AUTHORIZATION_3GPP = 300  # DIAMETER BASE (3GPP) RFC 3589
SERVER_ASSIGNMENT_3GPP = 301  # DIAMETER BASE (3GPP) RFC 3589
LOCATION_INFO_3GPP = 302  # DIAMETER BASE (3GPP) RFC 3589
MULTIMEDIA_AUTH_3GPP = 303  # DIAMETER BASE (3GPP) RFC 3589
REGISTRATION_TERMINATION = 304  # DIAMETER BASE (3GPP) RFC 3589
PUSH_PROFILE_3GPP = 305  # DIAMETER BASE (3GPP) RFC 3589
USER_DATA = 306  # DIAMETER BASE (3GPP) RFC 3589
PROFILE_UPDATE = 307  # DIAMETER BASE (3GPP) RFC 3589
SUBSCRIBE_NOTIFICATIONS = 308  # DIAMETER BASE (3GPP) RFC 3589
PUSH_NOTIFICATION = 309  # DIAMETER BASE (3GPP) RFC 3589
BOOTSTRAPPING_INFO = 310  # DIAMETER BASE (3GPP) RFC 3589
MESSAGE_PROCESS = 311  # DIAMETER BASE (3GPP) RFC 3589
UPDATE_LOCATION = 316  # 3GPP TS 29.272 [RFC 5516]
CANCEL_LOCATION = 317  # 3GPP TS 29.272 [RFC 5516]
AUTHENTICATION_INFORMATION = 318  # 3GPP TS 29.272 [RFC 5516]
INSERT_SUBSCRIBER_DATA = 319  # 3GPP TS 29.272 [RFC 5516]
DELETE_SUBSCRIBER_DATA = 320  # 3GPP TS 29.272 [RFC 5516]
PURGE_UE = 321  # 3GPP TS 29.272 [RFC 5516]
NOTIFY = 323  # 3GPP TS 29.272 [RFC 5516]
PROVIDE_LOCATION = 8388620  # 3GPP-LCS-SLG (APPLICATION-ID 16777255)
ROUTING_INFO = 8388622  # 3GPP-LCS-SLH (APPLICATION-ID 16777291)
CONFIGURATION_INFORMATION = 8388718  # S6T PER 3GPP TS 29.336
REPORTING_INFORMATION = 8388719  # S6T PER 3GPP TS 29.338
NIDD_INFORMATION = 8388726  # S6T PER 3GPP TS 29.340

# Create a dictionary of all command codes to command name
command_code_names = {
    ABORT_SESSION: "ABORT_SESSION",
    ACCOUNTING: "ACCOUNTING",
    CAPABILITIES_EXCHANGE: "CAPABILITIES_EXCHANGE",
    DEVICE_WATCHDOG: "DEVICE_WATCHDOG",
    DISCONNECT_PEER: "DISCONNECT_PEER",
    RE_AUTH: "RE_AUTH",
    SESSION_TERMINATION: "SESSION_TERMINATION",
    AA_MOBILE_NODE: "AA_MOBILE_NODE",
    HOME_AGENT_MIP: "HOME_AGENT_MIP",
    AA: "AA",
    DIAMETER_EAP: "DIAMETER_EAP",
    CREDIT_CONTROL: "CREDIT_CONTROL",
    USER_AUTHORIZATION: "USER_AUTHORIZATION",
    SERVER_ASSIGNMENT: "SERVER_ASSIGNMENT",
    LOCATION_INFO: "LOCATION_INFO",
    MULTIMEDIA_AUTH: "MULTIMEDIA_AUTH",
    REGISTRATION_TERMINATION: "REGISTRATION_TERMINATION",
    PUSH_PROFILE: "PUSH_PROFILE",
    USER_AUTHORIZATION_3GPP: "USER_AUTHORIZATION_3GPP",
    SERVER_ASSIGNMENT_3GPP: "SERVER_ASSIGNMENT_3GPP",
    LOCATION_INFO_3GPP: "LOCATION_INFO_3GPP",
    MULTIMEDIA_AUTH_3GPP: "MULTIMEDIA_AUTH_3GPP",
    REGISTRATION_TERMINATION: "REGISTRATION_TERMINATION",
    PUSH_PROFILE_3GPP: "PUSH_PROFILE_3GPP",
    USER_DATA: "USER_DATA",
    PROFILE_UPDATE: "PROFILE_UPDATE",
    SUBSCRIBE_NOTIFICATIONS: "SUBSCRIBE_NOTIFICATIONS",
    PUSH_NOTIFICATION: "PUSH_NOTIFICATION",
    BOOTSTRAPPING_INFO: "BOOTSTRAPPING_INFO",
    MESSAGE_PROCESS: "MESSAGE_PROCESS",
    UPDATE_LOCATION: "UPDATE_LOCATION",
    CANCEL_LOCATION: "CANCEL_LOCATION",
    AUTHENTICATION_INFORMATION: "AUTHENTICATION_INFORMATION",
    INSERT_SUBSCRIBER_DATA: "INSERT_SUBSCRIBER_DATA",
    DELETE_SUBSCRIBER_DATA: "DELETE_SUBSCRIBER_DATA",
    PURGE_UE: "PURGE_UE",
    NOTIFY: "NOTIFY",
    PROVIDE_LOCATION: "PROVIDE_LOCATION",
    ROUTING_INFO: "ROUTING_INFO",
    CONFIGURATION_INFORMATION: "CONFIGURATION_INFORMATION",
    REPORTING_INFORMATION: "REPORTING_INFORMATION",
    NIDD_INFORMATION: "NIDD_INFORMATION",
}

APP_ID_BASE_COMMON = 0
APP_ID_BASE_ACOUNTING = 3
APP_ID_CREDIT_CONTROL = 4
APP_ID_3GPP_CX_DX = 16777216
APP_ID_3GPP_SH = 16777217
APP_ID_3GPP_RX = 16777236
APP_ID_3GPP_GX = 16777238
APP_ID_3GPP_S6A_S6D = 16777251
APP_ID_3GPP_S13 = 16777252
APP_ID_3GPP_SLG = 16777255
APP_ID_3GPP_S6T = 16777345

# Create a dictionary of all APP_ID to application name
app_id_names = {
    APP_ID_BASE_COMMON: "BASE COMMON",
    APP_ID_BASE_ACOUNTING: "BASE ACCOUNTING",
    APP_ID_CREDIT_CONTROL: "CREDIT CONTROL",
    APP_ID_3GPP_CX_DX: "Cx/Dx",
    APP_ID_3GPP_SH: "Sh",
    APP_ID_3GPP_RX: "Rx",
    APP_ID_3GPP_GX: "Gx",
    APP_ID_3GPP_S6A_S6D: "S6a/S6d",
    APP_ID_3GPP_S13: "S13",
    APP_ID_3GPP_SLG: "SLg",
    APP_ID_3GPP_S6T: "S6t",
}


class AVP(dpkt.diameter.AVP):  # type: ignore
    """
    Diameter AVP with some fixes.
    """

    def unpack(self, buf: bytes) -> None:
        """
        Override unpack method to fix the length field.
        """
        dpkt.Packet.unpack(self, buf)
        self_len = getattr(self, "len")
        self.len = (
            (compat_ord(self_len[0]) << 16)
            | (compat_ord(self_len[1]) << 8)
            | (compat_ord(self_len[2]))
        )

        self.data = getattr(self, "data")

        padding = (4 - (self.len % 4)) % 4

        if self.vendor_flag:
            self.vendor = struct.unpack(">I", self.data[:4])[0]
            self.data = self.data[4 : self.len - getattr(self, "__hdr_len__") + padding]
        else:
            self.data = self.data[: self.len - getattr(self, "__hdr_len__") + padding]


class Diameter(dpkt.diameter.Diameter):  # type: ignore
    """
    Diameter packet with AVP fixes.
    """

    def unpack(self, buf: bytes) -> None:
        """
        Unpack Diameter packet with new AVP class.
        """
        dpkt.Packet.unpack(self, buf)
        self_cmd = getattr(self, "cmd")
        self_len = getattr(self, "len")
        self.cmd = (
            (compat_ord(self_cmd[0]) << 16)
            | (compat_ord(self_cmd[1]) << 8)
            | (compat_ord(self_cmd[2]))
        )
        self.len = (
            (compat_ord(self_len[0]) << 16)
            | (compat_ord(self_len[1]) << 8)
            | (compat_ord(self_len[2]))
        )
        self.data = getattr(self, "data")
        self.data = self.data[: self.len - getattr(self, "__hdr_len__")]

        l_ = []
        while self.data:
            avp = AVP(self.data)
            l_.append(avp)
            self.data = self.data[len(avp) :]
        self.data = self.avps = l_


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the Diameter protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Try to decode the application layer as TWAMP.

    Args:
        packet: E2E Packet object.
        transport: Transport layer dpkt object.
        app: Application packet.

    Returns:
        Diameter data dpkt object.
    """
    diameter = None

    # First check if chunk flags indicate first segment
    # second lowest bit of flags is set
    if getattr(packet, "transport_type") in ("SCTP",) and isinstance(
        transport, dpkt.sctp.SCTP
    ):
        # No data
        setattr(packet, "app_type", "Diameter")
        setattr(packet, "app_response", "No Data (SACK)")
    elif (
        getattr(packet, "transport_type") in ("SCTP",)
        and isinstance(transport, dpkt.sctp.Chunk)
        and (getattr(transport, "flags") & 0b00000010) >> 1 == 0
    ):
        setattr(packet, "app_type", "Diameter")
        setattr(packet, "app_request", "CHUNK :" + app.hex())
        setattr(packet, "app_response", "CHUNK")
    # TODO: TCP Chunk
    else:
        setattr(packet, "app_type", "Diameter")
        if getattr(packet, "transport_type") in ("SCTP",) and isinstance(
            transport, dpkt.sctp.Chunk
        ):
            pointer = 12
        else:
            pointer = 0

        try:
            diameter = Diameter(app[pointer:])
            diameter_data = getattr(diameter, "data")
            if getattr(diameter, "v") == 1:
                try:
                    setattr(
                        packet,
                        "app_session",
                        app_id_names[getattr(diameter, "app_id")]
                        + " "
                        + command_code_names[getattr(diameter, "cmd")],
                    )
                    setattr(packet, "app_seq", None)
                    # if diameter flags indicate request
                    if getattr(diameter, "request_flag"):
                        setattr(packet, "app_request", "REQUEST: " + str(diameter_data))
                    else:
                        setattr(
                            packet, "app_response", "RESPONSE: " + str(diameter_data)
                        )
                except KeyError:
                    pass
        except (dpkt.UnpackError, struct.error, AttributeError):
            diameter = None

    if diameter is None:
        setattr(packet, "app_type", None)
        setattr(packet, "app_seq", None)
        setattr(packet, "app_request", None)
        setattr(packet, "app_response", None)
        return None

    return bytes(diameter_data)
