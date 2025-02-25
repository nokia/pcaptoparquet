"""
TWAMP Light Protocol extension module for dpkt.
"""

from typing import Any, Optional

import dpkt

NTP_EPOCH_OFFSET = 2208988800


class TWAMP(dpkt.Packet):  # type: ignore
    """
    TWAMP Light implementation.
    """

    @classmethod
    def ntp_to_timestamp(cls, ntp_seconds: int, ntp_fraction: int) -> float:
        """
        Convert NTP timestamp to Unix timestamp.
        """
        # NTP epoch offset in seconds (from 1900 to 1970)

        # Calculate seconds since Unix epoch
        unix_seconds = ntp_seconds - NTP_EPOCH_OFFSET

        # Calculate microseconds from the fractional part
        microseconds = int((ntp_fraction * 1.0e6) / (1 << 32))

        # Combine seconds and microseconds to form the final timestamp
        timestamp = unix_seconds + microseconds / 1.0e6

        return timestamp

    class LightRequest(dpkt.Packet):  # type: ignore
        """
        TWAMP Light Request packet.
        """

        __hdr__ = (
            ("seq", "I", 0),
            ("seconds", "I", 0),
            ("fraction", "I", 0),
            ("error", "H", 0),
        )

    class Response(dpkt.Packet):  # type: ignore
        """
        TWAMP Light Response packet.
        """

        __hdr__ = (
            ("seq", "I", 0),
            ("seconds", "I", 0),
            ("fraction", "I", 0),
            ("error", "H", 0),
            ("mbz", "H", 0),
            ("rcv_seconds", "I", 0),
            ("rcv_fraction", "I", 0),
            ("sender_seq", "I", 0),
            ("sender_seconds", "I", 0),
            ("sender_fraction", "I", 0),
            ("sender_error", "H", 0),
            ("sender_mbz", "H", 0),
            ("sender_ttl", "B", 0),
        )

        def unpack(self, buf: bytes) -> None:
            """
            Unpack TWAMP Light Response packet.
            """
            dpkt.Packet.unpack(self, buf)
            if getattr(self, "mbz") > 0 or getattr(self, "sender_mbz") > 0:
                raise dpkt.UnpackError(
                    "Invalid TWAMP Response. MBZ fields must be zero."
                )

    def unpack(self, buf: bytes) -> None:
        """
        Unpack TWAMP Light packet.
        """
        # Try to unpack as a Response, if that fails, unpack as a LightRequest
        try:
            self.data = self.Response(buf)
        except (KeyError, dpkt.UnpackError):
            self.data = self.LightRequest(buf)

        setattr(self, self.data.__class__.__name__.lower(), self.data)


def get_metadata() -> dict[str, str]:
    """
    Get additional metadata for the TWAMP Light protocol.
    """
    return {}


def decode(packet: Any, transport: Any, app: Any) -> Optional[bytes]:
    """
    Try to decode the application layer as TWAMP.

    Args:
        app: Application packet.

    Returns:
        TWAMP data dpkt object.
    """
    twamp = None

    if not isinstance(transport, dpkt.udp.UDP):
        return None

    try:
        twamp = TWAMP(app)
        twamp_reqres = getattr(twamp, "data")

        # Check if timestamp is valid
        delta = abs(
            getattr(packet, "utc_date_time").timestamp()
            - TWAMP.ntp_to_timestamp(
                getattr(twamp_reqres, "seconds"), getattr(twamp_reqres, "fraction")
            )
        )

        if delta < 100:  # More than 100 seconds

            # Check if it is a Request or a Response
            if isinstance(twamp_reqres, TWAMP.LightRequest):
                setattr(packet, "app_type", "TWAMP")
                data_seq = getattr(twamp_reqres, "seq")
                setattr(packet, "app_session", data_seq)
                setattr(packet, "app_seq", data_seq)
                twamp_data = getattr(twamp_reqres, "data")
                setattr(twamp_reqres, "data", b"")
                setattr(packet, "app_request", repr(twamp_reqres))

            elif isinstance(twamp_reqres, TWAMP.Response):
                setattr(packet, "app_type", "TWAMP")
                data_seq = getattr(twamp_reqres, "seq")
                setattr(packet, "app_session", data_seq)
                setattr(packet, "app_seq", data_seq)
                twamp_data = getattr(twamp_reqres, "data")
                setattr(twamp_reqres, "data", b"")
                setattr(packet, "app_response", repr(twamp_reqres))
            else:
                twamp_data = None
        else:
            twamp_data = None

    except dpkt.UnpackError:
        # do nothing...
        twamp_data = None

    # Check timestamp

    return bytes(twamp_data) if twamp_data else None
