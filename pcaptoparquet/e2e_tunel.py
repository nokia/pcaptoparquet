# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""
This module defines the E2ETunel and E2ETunelList classes.

E2ETunel represents an end-to-end tunnel with the following attributes:
- Type
- Source
- Destination
- Overhead
- IP ID
- IP TTL

E2ETunelList represents a list of E2ETunel objects. It takes an outer IP packet as input
and extracts the tunneled packets from it. The tunneled packets can be of two types:
GTP-U or VxLAN. The E2ETunelList class provides methods to convert the list of tunneled
packets to JSON format.

Example usage:
    outer_ip = dpkt.ip.IP(...)
    tunel_list = E2ETunelList(outer_ip)
    print(tunel_list)

Output:
    E2ETunelList(
        E2ETunel(
            type='GTP-U',
            id=123,
            src='192.168.0.1',
            dst='192.168.0.2',
            len=100,
            pkt_id=456,
            pkt_ttl=64,
            dscp=0
        ),
        E2ETunel(
            type='VxLAN',
            id=789,
            src='192.168.0.3',
            dst='192.168.0.4',
            len=200,
            pkt_id=789,
            pkt_ttl=128,
            dscp=0
        )
    )
"""
import struct
from typing import Any

import dpkt
from dpkt.utils import inet_to_str


class E2ETunel:
    """
    Represents an end-to-end tunnel with the following attributes:
         - Type
         - Source
         - Destination
         - Overhead
         - IP ID
         - IP TTL
    """

    def __init__(self, tunel_info: dict[str, Any]) -> None:
        for attr in tunel_info:
            if attr in [
                "type",
                "id",
                "src",
                "dst",
                "len",
                "pkt_id",
                "pkt_ttl",
                "dscp",
                "ecn",
            ]:
                setattr(self, attr, tunel_info[attr])
            else:
                raise AttributeError(f"Unknown attribute: {attr}")

    def __repr__(self) -> str:
        l_ = []
        for attr in self.__dict__:
            l_.append(f"{attr}={repr(getattr(self, attr))}")
        return f"{self.__class__.__name__}({', '.join(l_)})"

    def to_json(self) -> dict[str, Any]:
        """
        Convert the E2ETunel object to a dictionary.
        """
        d_ = {}
        for attr in self.__dict__:
            d_[attr] = getattr(self, attr)
        return d_


class E2ETunelList:
    """
    Represents a list of E2ETunel objects. It takes an outer IP packet as input
    and extracts the tunneled packets from it. The tunneled packets can be of two types:
    GTP-U or VxLAN.
    """

    @staticmethod
    def decode_id(ipkt: dpkt.Packet) -> int:
        """
        Decode the id of the IP packet.
        """
        pid = 0
        try:
            pid = getattr(ipkt, "id")
        except AttributeError:
            pid = 0
        return pid if pid else 0

    @staticmethod
    def decode_ttl(ipkt: dpkt.Packet) -> int:
        """
        Decode the ttl of the IP packet.
        Throws AttributeError if the packet does not have a ttl field.
        """
        ttl = 0
        try:
            ttl = getattr(ipkt, "ttl")
        except AttributeError:
            ttl = getattr(ipkt, "hlim")
        return ttl

    @staticmethod
    def decode_length(ipkt: dpkt.Packet, delta: int = 0) -> int:
        """
        Decode the length of the IP packet.
        Throws AttributeError if the packet does not have a length field.
        """
        ll = 0
        try:
            ll = getattr(ipkt, "len") - delta
        except AttributeError:
            ll = getattr(ipkt, "plen")
        return ll if ll and ll > 0 else 0

    @staticmethod
    def decode_dscp(ipkt: dpkt.Packet) -> int:
        """
        Decode the QoS of the IP packet.
        Throws AttributeError if the packet does not have a QoS field.
        """
        qos = 0
        try:
            qos = getattr(ipkt, "tos") >> 2
        except AttributeError:
            qos = getattr(ipkt, "fc") >> 2
        return qos

    @staticmethod
    def decode_ecn(ipkt: dpkt.Packet) -> int:
        """
        Decode the QoS of the IP packet.
        Throws AttributeError if the packet does not have a QoS field.
        """
        ecn = 0
        try:
            ecn = getattr(ipkt, "tos") & 0x03
        except AttributeError:
            ecn = getattr(ipkt, "fc") & 0x03
        return ecn

    @staticmethod
    def decode_frag(ipkt: dpkt.Packet) -> bool:
        """
        Decode the fragmentation of the IP packet.
        Throws AttributeError if the packet does not have a fragmentation field.
        """
        ip_frag = False
        try:
            ip_frag = bool(getattr(ipkt, "mf"))
        except AttributeError:
            try:
                ip_frag = bool(getattr(ipkt, "extension_hdrs")[44].m_flag)
            except (AttributeError, KeyError):
                ip_frag = False
        return ip_frag

    @staticmethod
    def decode_gtp(buf: bytes) -> tuple[Any, Any, Any]:
        """
        Decode GTP-U packet and extract the TEID, payload length and inner IP packet.

        TODO: GTP Extension Headers
        QoS Flow Identifier (QFI)
           – Used to identify the QoS flow to be used
             (Pretty self explanatory)
        Reflective QoS Indicator (RQI)
           – To indicate reflective QoS is supported
             for the encapsulated packet
        Paging Policy Presence (PPP)
           – To indicate support for Paging Policy
             Indicator (PPI)
        Paging Policy Indicator (PPI)
           – Sets parameters of paging policy
             differentiation to be applied
        QoS Monitoring Packet
           – Indicates packet is used for QoS Monitoring
             and DL & UL Timestamps to come
        UL/DL Sending Time Stamps
           – 64 bit timestamp generated at the time
             the UPF or UE encodes the packet
        UL/DL Received Time Stamps
           – 64 bit timestamp generated at the time
             the UPF or UE received the packet
        UL/DL Delay Indicators
           – Indicates Delay Results to come
        UL/DL Delay Results
           – Delay measurement results
        Sequence Number Presence
           – Indicates if QFI sequence number to come
        UL/DL QFI Sequence Number
           – Sequence number as assigned by the UPF
             or gNodeB
        """

        if len(buf) < 8:
            return 0, -1, None

        gtp_len = struct.unpack("!H", buf[2:4])[0] + 8
        teid = struct.unpack("!I", buf[4:8])[0]
        plen = 0
        next_ip = None

        ii = 8
        if ii < gtp_len - 1 and len(buf) > ii + 1:

            firstoctect = struct.unpack("!B", buf[ii : ii + 1])[0] & 0xFF  # >> 4

            while (
                not (firstoctect == 0x45 or firstoctect & 0xF0 == 0x60)
                and ii < gtp_len - 1
                and len(buf) > ii + 1
            ):
                ii = ii + 1
                firstoctect = struct.unpack("!B", buf[ii : ii + 1])[0] & 0xFF  # >> 4

            plen = -1

            if firstoctect == 0x45:
                try:
                    next_ip = dpkt.ip.IP(buf[ii:])
                except dpkt.UnpackError:
                    next_ip = None
                    plen = -1

            elif firstoctect & 0xF0 == 0x60:
                try:
                    next_ip = dpkt.ip6.IP6(buf[ii:])
                except dpkt.UnpackError:
                    next_ip = None
                    plen = -1

        if next_ip:
            plen = E2ETunelList.decode_length(next_ip, 20)

        return teid, plen, next_ip

    @staticmethod
    def decode_vxlan(buf: bytes) -> tuple[Any, Any, Any]:
        """
        Decode VxLAN packet and extract the VNI and inner IP packet.
        """
        if len(buf) < 4:
            return 0, -1, None

        teid = struct.unpack("!I", buf[3:7])[0] & 0x00FFFFFF
        plen = 0
        try:
            next_ip = dpkt.ethernet.Ethernet(buf[8:]).data
        except dpkt.UnpackError:
            next_ip = None
            plen = -1

        if next_ip:
            plen = E2ETunelList.decode_length(next_ip)

        return teid, plen, next_ip

    def __init__(self, outerip: dpkt.Packet) -> None:
        _ip_ = outerip
        _new_ip_ = outerip
        self.tunels = []
        while _ip_ and isinstance(_ip_.data, dpkt.udp.UDP):
            # Sorted list to have the unique ID regardless of
            # the packet direction.
            # Need to use getattr because dpkt properties are
            # created dynamically. See __hdr__ in dpkt.ip.IP.
            ips = [inet_to_str(getattr(_ip_, "src")), inet_to_str(getattr(_ip_, "dst"))]
            pkt_id = E2ETunelList.decode_id(_ip_)
            pkt_ttl = E2ETunelList.decode_ttl(_ip_)
            length = E2ETunelList.decode_length(_ip_)
            dscp = E2ETunelList.decode_dscp(_ip_)
            ecn = E2ETunelList.decode_ecn(_ip_)

            udp = _ip_.data

            # 2152	GTP user data messages (GTP-U)
            if getattr(udp, "sport") == 2152 or getattr(udp, "dport") == 2152:
                teid, plen, _ip_ = E2ETunelList.decode_gtp(udp.data)
                if not plen < 0:
                    self.tunels.append(
                        E2ETunel(
                            {
                                "type": "GTP-U",
                                "id": teid,
                                "src": ips[0],
                                "dst": ips[1],
                                "len": length - plen,
                                "pkt_id": pkt_id,
                                "pkt_ttl": pkt_ttl,
                                "dscp": dscp,
                                "ecn": ecn,
                            }
                        )
                    )

                if not plen > 0:  # No inner IP packet
                    _new_ip_ = _ip_
                    _ip_ = None

            # 4789	Virtual eXtensible Local Area Network (VxLAN)
            elif getattr(udp, "sport") == 4789 or getattr(udp, "dport") == 4789:
                teid, plen, _ip_ = E2ETunelList.decode_vxlan(udp.data)
                if not plen < 0:
                    self.tunels.append(
                        E2ETunel(
                            {
                                "type": "VxLAN",
                                "id": teid,
                                "src": ips[0],
                                "dst": ips[1],
                                "len": length - plen,
                                "pkt_id": pkt_id,
                                "pkt_ttl": pkt_ttl,
                                "dscp": dscp,
                                "ecn": ecn,
                            }
                        )
                    )

                if not plen > 0:  # No inner IP packet
                    _new_ip_ = _ip_
                    _ip_ = None

            else:
                _new_ip_ = _ip_
                _ip_ = None

        if _ip_:
            self.ip = _ip_
        else:
            self.ip = _new_ip_

    def __repr__(self) -> str:
        l_ = []
        for tt in self.tunels:
            l_.append(repr(tt))
        return f"{self.__class__.__name__}({', '.join(l_)})"

    def to_json(self) -> list[dict[str, Any]]:
        """
        Convert the E2ETunelList object to a list of dictionaries.
        """
        l_ = []
        for tt in self.tunels:
            l_.append(tt.to_json())
        return l_
