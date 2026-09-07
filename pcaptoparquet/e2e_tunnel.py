# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""
This module defines the E2ETunnel and E2ETunnelList classes.

E2ETunnel represents an end-to-end tunnel with the following attributes:
- Type
- Source
- Destination
- Overhead
- IP ID
- IP TTL

E2ETunnelList represents a list of E2ETunnel objects. It takes an outer IP packet as
input and extracts the tunneled packets from it. GTP-U and VxLAN are supported.
L2TPv2, L2TPv3, and GRE unwrapping are experimental. The E2ETunnelList class provides
methods to convert the list of tunneled packets to JSON format.

Example usage:
    outer_ip = dpkt.ip.IP(...)
    tunnel_list = E2ETunnelList(outer_ip)
    print(tunnel_list)

Output:
    E2ETunnelList(
        E2ETunnel(
            type='GTP-U',
            id=123,
            src='192.168.0.1',
            dst='192.168.0.2',
            len=100,
            pkt_id=456,
            pkt_ttl=64,
            dscp=0
        ),
        E2ETunnel(
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
from typing import Any, Optional, Union

import dpkt
from dpkt.utils import inet_to_str

_InnerIP = Union[dpkt.ip.IP, dpkt.ip6.IP6]
_L2TPResult = tuple[str, int, int, Any]


class E2ETunnel:
    """
    Represents an end-to-end tunnel with the following attributes:
         - Type
         - Source
         - Destination
         - Overhead
         - IP ID
         - IP TTL
    """

    type: str
    id: int
    src: str
    dst: str
    len: int
    pkt_id: int
    pkt_ttl: int
    dscp: int
    ecn: int

    def __init__(self, tunnel_info: dict[str, Any]) -> None:
        self.type = ""
        self.id = 0
        self.src = ""
        self.dst = ""
        self.len = 0
        self.pkt_id = 0
        self.pkt_ttl = 0
        self.dscp = 0
        self.ecn = 0
        for attr in tunnel_info:
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
                setattr(self, attr, tunnel_info[attr])
            else:
                raise AttributeError(f"Unknown attribute: {attr}")

    def __repr__(self) -> str:
        l_ = []
        for attr in self.__dict__:
            l_.append(f"{attr}={repr(getattr(self, attr))}")
        return f"{self.__class__.__name__}({', '.join(l_)})"

    def to_json(self) -> dict[str, Any]:
        """
        Convert the E2ETunnel object to a dictionary.
        """
        d_ = {}
        for attr in self.__dict__:
            d_[attr] = getattr(self, attr)
        return d_


class E2ETunnelList:
    """
    Represents a list of E2ETunnel objects. It takes an outer IP packet as input
    and extracts the tunneled packets from it. GTP-U and VxLAN are supported.
    L2TPv2, L2TPv3, and GRE unwrapping are experimental.
    """

    UDP_PORT_GTP = 2152
    UDP_PORT_VXLAN = 4789
    UDP_PORT_L2TP = 1701
    IP_PROTO_GRE = 47
    IP_PROTO_L2TP = 115

    L2TP_T_BIT = 0x8000
    L2TP_L_BIT = 0x4000
    L2TP_S_BIT = 0x0800
    L2TP_O_BIT = 0x0200

    GRE_C_BIT = 0x8000
    GRE_R_BIT = 0x4000
    GRE_K_BIT = 0x2000
    GRE_S_BIT = 0x1000
    GRE_A_BIT = 0x0080
    GRE_VER_MASK = 0x0007

    ETH_TYPE_IP = 0x0800
    ETH_TYPE_IPV6 = 0x86DD
    ETH_TYPE_TEB = 0x6558
    ETH_TYPE_PPP = 0x880B
    ETH_TYPE_ERSPAN = 0x88BE
    GRE_PROTO_IPV4 = 0x0004
    GRE_PROTO_IPV6 = 0x0029

    _L2TP_MISS: _L2TPResult = ("", 0, -1, None)

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
        return int(ttl)

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
        return int(qos)

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
        return int(ecn)

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
    def _is_gre(data: Any) -> bool:
        gre_mod = getattr(dpkt, "gre", None)
        gre_cls = getattr(gre_mod, "GRE", None) if gre_mod is not None else None
        return gre_cls is not None and isinstance(data, gre_cls)

    @staticmethod
    def _is_inner_ip(pkt: Any) -> bool:
        return isinstance(pkt, (dpkt.ip.IP, dpkt.ip6.IP6))

    @staticmethod
    def _payload_bytes(data: Any) -> bytes:
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
        try:
            return bytes(data)
        except (TypeError, ValueError):
            return b""

    @staticmethod
    def _ip_proto(ipkt: dpkt.Packet) -> int:
        if isinstance(ipkt, dpkt.ip.IP):
            return int(getattr(ipkt, "p"))
        try:
            return int(getattr(ipkt, "p"))
        except AttributeError:
            try:
                return int(getattr(ipkt, "nxt"))
            except AttributeError:
                return -1

    @staticmethod
    def _should_walk(ipkt: dpkt.Packet) -> bool:
        data = getattr(ipkt, "data", None)
        if isinstance(data, dpkt.udp.UDP):
            return True
        if E2ETunnelList._is_gre(data):
            return True
        proto = E2ETunnelList._ip_proto(ipkt)
        return proto in (E2ETunnelList.IP_PROTO_GRE, E2ETunnelList.IP_PROTO_L2TP)

    @staticmethod
    def _inner_with_plen(
        inner: Optional[_InnerIP], delta: int = 20
    ) -> tuple[int, Optional[_InnerIP]]:
        if inner is None:
            return -1, None
        plen = E2ETunnelList.decode_length(inner, delta)
        if plen > 0:
            return plen, inner
        return -1, None

    @staticmethod
    def decode_raw_ip(buf: bytes) -> Optional[_InnerIP]:
        """Parse a raw IPv4 or IPv6 datagram from buf."""
        if not buf:
            return None
        ver = buf[0] >> 4
        try:
            if ver == 4:
                return dpkt.ip.IP(buf)
            if ver == 6:
                return dpkt.ip6.IP6(buf)
        except (dpkt.UnpackError, struct.error):
            return None
        return None

    @staticmethod
    def decode_ethernet_ip(buf: bytes) -> Optional[_InnerIP]:
        """Parse Ethernet (and VLAN) until an inner IPv4/IPv6 packet is found."""
        if not buf:
            return None
        try:
            inner: Any = dpkt.ethernet.Ethernet(buf).data
        except (dpkt.UnpackError, struct.error):
            return None
        while inner is not None and not E2ETunnelList._is_inner_ip(inner):
            try:
                inner = inner.data
            except AttributeError:
                return None
        if E2ETunnelList._is_inner_ip(inner):
            return inner
        return None

    @staticmethod
    def decode_ppp_ip(buf: bytes) -> Optional[_InnerIP]:
        """Parse PPP (optional HDLC) and return an inner IPv4/IPv6 packet."""
        if not buf:
            return None
        offset = 0
        if len(buf) >= 2 and buf[0] == 0xFF and buf[1] == 0x03:
            offset = 2
        if offset >= len(buf):
            return None
        if buf[offset] & 0x01:
            proto = buf[offset]
            offset += 1
        else:
            if offset + 2 > len(buf):
                return None
            proto = (buf[offset] << 8) | buf[offset + 1]
            offset += 2
        payload = buf[offset:]
        if proto in (0x0021, 0x21):
            try:
                return dpkt.ip.IP(payload)
            except (dpkt.UnpackError, struct.error):
                return None
        if proto in (0x0057, 0x57):
            try:
                return dpkt.ip6.IP6(payload)
            except (dpkt.UnpackError, struct.error):
                return None
        return None

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
            plen = E2ETunnelList.decode_length(next_ip, 20)

        return teid, plen, next_ip

    @staticmethod
    def decode_vxlan(buf: bytes) -> tuple[Any, Any, Any]:
        """
        Decode VxLAN packet and extract the VNI and inner IP packet.
        """
        if len(buf) < 8:
            return 0, -1, None

        teid = struct.unpack("!I", buf[3:7])[0] & 0x00FFFFFF
        next_ip = E2ETunnelList.decode_ethernet_ip(buf[8:])
        if next_ip is None:
            return teid, -1, None
        plen = E2ETunnelList.decode_length(next_ip)
        return teid, plen, next_ip

    @staticmethod
    def _l2tpv2_user_payload(buf: bytes, flags: int) -> Optional[tuple[int, bytes]]:
        """Return (packed_id, payload) for an L2TPv2 data header, or None."""
        offset = 2
        msg_end = len(buf)
        if flags & E2ETunnelList.L2TP_L_BIT:
            if offset + 2 > len(buf):
                return None
            length = struct.unpack("!H", buf[offset : offset + 2])[0]
            offset += 2
            if length < offset + 4:
                return None
            msg_end = min(len(buf), length)
        if offset + 4 > msg_end:
            return None
        tunnel_id, session_id = struct.unpack("!HH", buf[offset : offset + 4])
        offset += 4
        if flags & E2ETunnelList.L2TP_S_BIT:
            if offset + 4 > msg_end:
                return None
            offset += 4
        if flags & E2ETunnelList.L2TP_O_BIT:
            if offset + 2 > msg_end:
                return None
            offset_size = struct.unpack("!H", buf[offset : offset + 2])[0]
            offset += 2
            if offset + offset_size > msg_end:
                return None
            offset += offset_size
        packed_id = (tunnel_id << 16) | session_id
        return packed_id, buf[offset:msg_end]

    @staticmethod
    def _payload_to_inner(buf: bytes) -> tuple[int, Optional[_InnerIP]]:
        inner = E2ETunnelList.decode_ppp_ip(buf)
        if inner is None:
            inner = E2ETunnelList.decode_raw_ip(buf)
        return E2ETunnelList._inner_with_plen(inner)

    @staticmethod
    def _l2tpv3_payload_to_inner(buf: bytes) -> tuple[int, Optional[_InnerIP]]:
        inner = E2ETunnelList.decode_ppp_ip(buf)
        if inner is None:
            inner = E2ETunnelList.decode_ethernet_ip(buf)
        if inner is None:
            inner = E2ETunnelList.decode_raw_ip(buf)
        return E2ETunnelList._inner_with_plen(inner)

    @staticmethod
    def decode_l2tpv3_data(buf: bytes) -> _L2TPResult:
        """Decode L2TPv3 data (32-bit Session ID, optional cookie / L2 sublayer)."""
        if len(buf) < 4:
            return E2ETunnelList._L2TP_MISS
        session_id = struct.unpack("!I", buf[0:4])[0]
        if session_id == 0:
            return E2ETunnelList._L2TP_MISS
        for off in (4, 8, 12, 16):
            if off >= len(buf):
                break
            plen, inner = E2ETunnelList._l2tpv3_payload_to_inner(buf[off:])
            if plen > 0 and inner is not None:
                return "L2TPv3", session_id, plen, inner
        return "L2TPv3", session_id, -1, None

    @staticmethod
    def decode_l2tp(buf: bytes, over_ip: bool = False) -> _L2TPResult:
        """
        Experimental: decode L2TPv2 or L2TPv3 and extract the inner IP packet.

        Returns (type, id, plen, inner_ip). plen < 0 means a miss.
        """
        if len(buf) < 2:
            return E2ETunnelList._L2TP_MISS

        try:
            flags = struct.unpack("!H", buf[0:2])[0]
        except struct.error:
            return E2ETunnelList._L2TP_MISS
        ver = flags & 0x000F
        t_bit = bool(flags & E2ETunnelList.L2TP_T_BIT)

        if over_ip:
            if ver == 3 and t_bit:
                return E2ETunnelList._L2TP_MISS
            return E2ETunnelList.decode_l2tpv3_data(buf)

        if ver == 3:
            return E2ETunnelList._L2TP_MISS
        if ver == 2:
            if t_bit:
                return E2ETunnelList._L2TP_MISS
            parsed = E2ETunnelList._l2tpv2_user_payload(buf, flags)
            if parsed is not None:
                packed_id, payload = parsed
                plen, inner = E2ETunnelList._payload_to_inner(payload)
                if plen > 0 and inner is not None:
                    return "L2TPv2", packed_id, plen, inner
            return E2ETunnelList.decode_l2tpv3_data(buf)
        return E2ETunnelList.decode_l2tpv3_data(buf)

    @staticmethod
    def decode_gre(buf: bytes) -> tuple[int, int, Any]:
        """
        Experimental: decode GRE v0 (RFC 2784/2890) or PPTP GRE v1 from raw bytes.

        Returns (id, plen, inner_ip). plen < 0 means a miss.
        """
        if len(buf) < 4:
            return 0, -1, None
        try:
            flags, proto = struct.unpack("!HH", buf[0:4])
        except struct.error:
            return 0, -1, None
        ver = flags & E2ETunnelList.GRE_VER_MASK
        if flags & E2ETunnelList.GRE_R_BIT:
            return 0, -1, None

        offset = 4
        gre_id = 0
        if ver == 1:
            if offset + 4 > len(buf):
                return 0, -1, None
            _plen, call_id = struct.unpack("!HH", buf[offset : offset + 4])
            gre_id = call_id
            offset += 4
            if flags & E2ETunnelList.GRE_S_BIT:
                if offset + 4 > len(buf):
                    return 0, -1, None
                offset += 4
            if flags & E2ETunnelList.GRE_A_BIT:
                if offset + 4 > len(buf):
                    return 0, -1, None
                offset += 4
            plen, inner = E2ETunnelList._inner_with_plen(
                E2ETunnelList.decode_ppp_ip(buf[offset:])
            )
            if plen > 0 and inner is not None:
                return gre_id, plen, inner
            return gre_id, -1, None

        if ver != 0:
            return 0, -1, None

        if flags & E2ETunnelList.GRE_C_BIT:
            if offset + 4 > len(buf):
                return 0, -1, None
            offset += 4
        if flags & E2ETunnelList.GRE_K_BIT:
            if offset + 4 > len(buf):
                return 0, -1, None
            gre_id = struct.unpack("!I", buf[offset : offset + 4])[0]
            offset += 4
        if flags & E2ETunnelList.GRE_S_BIT:
            if offset + 4 > len(buf):
                return 0, -1, None
            offset += 4

        payload = buf[offset:]
        inner = None
        if proto in (
            E2ETunnelList.ETH_TYPE_IP,
            E2ETunnelList.ETH_TYPE_IPV6,
            E2ETunnelList.GRE_PROTO_IPV4,
            E2ETunnelList.GRE_PROTO_IPV6,
        ):
            inner = E2ETunnelList.decode_raw_ip(payload)
        elif proto == E2ETunnelList.ETH_TYPE_TEB:
            inner = E2ETunnelList.decode_ethernet_ip(payload)
        elif proto == E2ETunnelList.ETH_TYPE_PPP:
            inner = E2ETunnelList.decode_ppp_ip(payload)
        else:
            return gre_id, -1, None

        plen, inner = E2ETunnelList._inner_with_plen(inner)
        if plen > 0 and inner is not None:
            return gre_id, plen, inner
        return gre_id, -1, None

    @staticmethod
    def _next_tunnel(
        ipkt: dpkt.Packet,
    ) -> Optional[tuple[str, int, int, Any, bool]]:
        data = getattr(ipkt, "data", None)
        if isinstance(data, dpkt.udp.UDP):
            sport = int(getattr(data, "sport"))
            dport = int(getattr(data, "dport"))
            payload = E2ETunnelList._payload_bytes(data.data)
            if (
                sport == E2ETunnelList.UDP_PORT_GTP
                or dport == E2ETunnelList.UDP_PORT_GTP
            ):
                teid, plen, inner = E2ETunnelList.decode_gtp(payload)
                return "GTP-U", teid, plen, inner, False
            if (
                sport == E2ETunnelList.UDP_PORT_VXLAN
                or dport == E2ETunnelList.UDP_PORT_VXLAN
            ):
                teid, plen, inner = E2ETunnelList.decode_vxlan(payload)
                return "VxLAN", teid, plen, inner, False
            if (
                sport == E2ETunnelList.UDP_PORT_L2TP
                or dport == E2ETunnelList.UDP_PORT_L2TP
            ):
                ttype, tid, plen, inner = E2ETunnelList.decode_l2tp(
                    payload, over_ip=False
                )
                return ttype, tid, plen, inner, True
            return None

        proto = E2ETunnelList._ip_proto(ipkt)
        payload = E2ETunnelList._payload_bytes(data)
        if proto == E2ETunnelList.IP_PROTO_L2TP:
            ttype, tid, plen, inner = E2ETunnelList.decode_l2tp(payload, over_ip=True)
            return ttype, tid, plen, inner, True
        if proto == E2ETunnelList.IP_PROTO_GRE or E2ETunnelList._is_gre(data):
            tid, plen, inner = E2ETunnelList.decode_gre(payload)
            return "GRE", tid, plen, inner, True
        return None

    def _append_tunnel(
        self,
        ttype: str,
        tid: int,
        plen: int,
        ipkt: dpkt.Packet,
        length: int,
    ) -> None:
        ips = [
            inet_to_str(getattr(ipkt, "src")),
            inet_to_str(getattr(ipkt, "dst")),
        ]
        self.tunnels.append(
            E2ETunnel(
                {
                    "type": ttype,
                    "id": tid,
                    "src": ips[0],
                    "dst": ips[1],
                    "len": length - plen,
                    "pkt_id": E2ETunnelList.decode_id(ipkt),
                    "pkt_ttl": E2ETunnelList.decode_ttl(ipkt),
                    "dscp": E2ETunnelList.decode_dscp(ipkt),
                    "ecn": E2ETunnelList.decode_ecn(ipkt),
                }
            )
        )

    def __init__(self, outerip: dpkt.Packet) -> None:
        _ip_: Optional[dpkt.Packet] = outerip
        _new_ip_: Optional[dpkt.Packet] = outerip
        self.tunnels: list[E2ETunnel] = []
        self.ip: Optional[dpkt.Packet] = outerip
        while _ip_ is not None and E2ETunnelList._should_walk(_ip_):
            length = E2ETunnelList.decode_length(_ip_)
            result = E2ETunnelList._next_tunnel(_ip_)
            if result is None:
                _new_ip_ = _ip_
                _ip_ = None
                break
            ttype, tid, plen, inner, require_inner = result
            if require_inner:
                if plen > 0 and E2ETunnelList._is_inner_ip(inner):
                    self._append_tunnel(ttype, tid, plen, _ip_, length)
                    _ip_ = inner
                else:
                    _new_ip_ = _ip_
                    _ip_ = None
            else:
                if not plen < 0:
                    self._append_tunnel(ttype, tid, plen, _ip_, length)
                if not plen > 0:
                    _new_ip_ = inner
                    _ip_ = None
                else:
                    _ip_ = inner

        if _ip_:
            self.ip = _ip_
        else:
            self.ip = _new_ip_

    def __repr__(self) -> str:
        l_ = []
        for tt in self.tunnels:
            l_.append(repr(tt))
        return f"{self.__class__.__name__}({', '.join(l_)})"

    def to_json(self) -> list[dict[str, Any]]:
        """
        Convert the E2ETunnelList object to a list of dictionaries.
        """
        l_ = []
        for tt in self.tunnels:
            l_.append(tt.to_json())
        return l_
