# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for experimental L2TPv2 / L2TPv3 tunnel unwrapping."""

import datetime
import socket
import struct
import unittest
from typing import Optional

import dpkt

from pcaptoparquet import E2EConfig
from pcaptoparquet.e2e_packet import E2EPacket
from pcaptoparquet.e2e_tunnel import E2ETunnelList


def _ipv4(
    src: str,
    dst: str,
    data: bytes | dpkt.Packet,
    proto: int,
) -> dpkt.ip.IP:
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src),
        dst=socket.inet_aton(dst),
        p=proto,
        ttl=64,
        data=data,
    )
    return dpkt.ip.IP(bytes(ip))


def _ipv6(
    src: str,
    dst: str,
    data: bytes | dpkt.Packet,
    nxt: int,
) -> dpkt.ip6.IP6:
    ip6 = dpkt.ip6.IP6(
        src=socket.inet_pton(socket.AF_INET6, src),
        dst=socket.inet_pton(socket.AF_INET6, dst),
        nxt=nxt,
        data=data,
    )
    payload = bytes(ip6.data) if not isinstance(ip6.data, bytes) else ip6.data
    setattr(ip6, "plen", len(payload))
    return dpkt.ip6.IP6(bytes(ip6))


def _udp(sport: int, dport: int, payload: bytes) -> dpkt.udp.UDP:
    return dpkt.udp.UDP(sport=sport, dport=dport, data=payload)


def _inner_ipv4_udp(
    src: str = "10.0.0.1",
    dst: str = "10.0.0.2",
    sport: int = 4000,
    dport: int = 80,
    payload: bytes = b"inner",
) -> dpkt.ip.IP:
    return _ipv4(src, dst, _udp(sport, dport, payload), dpkt.ip.IP_PROTO_UDP)


def _inner_ipv6_udp() -> dpkt.ip6.IP6:
    return _ipv6(
        "2001:db8::1",
        "2001:db8::2",
        _udp(4000, 80, b"inner6"),
        dpkt.ip.IP_PROTO_UDP,
    )


def _ppp_ipv4(ip: dpkt.ip.IP, compressed: bool = False) -> bytes:
    proto = b"\x21" if compressed else b"\x00\x21"
    return b"\xff\x03" + proto + bytes(ip)


def _ppp_ipv6(ip6: dpkt.ip6.IP6) -> bytes:
    return b"\xff\x03\x00\x57" + bytes(ip6)


def _l2tpv2_hdr(
    tunnel_id: int,
    session_id: int,
    payload: bytes,
    flags: int = 0x0002,
    ns: int = 1,
    nr: int = 0,
    offset_size: int = 0,
    length_value: int | None = None,
) -> bytes:
    body = b""
    if flags & E2ETunnelList.L2TP_L_BIT:
        body += b"\x00\x00"
    body += struct.pack("!HH", tunnel_id, session_id)
    if flags & E2ETunnelList.L2TP_S_BIT:
        body += struct.pack("!HH", ns, nr)
    if flags & E2ETunnelList.L2TP_O_BIT:
        body += struct.pack("!H", offset_size) + (b"\x00" * offset_size)
    body += payload
    hdr = struct.pack("!H", flags)
    if flags & E2ETunnelList.L2TP_L_BIT:
        total = 2 + len(body) if length_value is None else length_value
        hdr += struct.pack("!H", total) + body[2:]
        return hdr
    return hdr + body


def _ethernet_ipv4(ip: dpkt.ip.IP, vlan: int | None = None) -> bytes:
    dst = b"\x00\x11\x22\x33\x44\x55"
    src = b"\x66\x77\x88\x99\xaa\xbb"
    if vlan is None:
        return bytes(
            dpkt.ethernet.Ethernet(
                dst=dst,
                src=src,
                type=dpkt.ethernet.ETH_TYPE_IP,
                data=ip,
            )
        )
    return dst + src + struct.pack("!HHH", 0x8100, vlan, 0x0800) + bytes(ip)


def _outer_udp_l2tp(payload: bytes, dport: int = 1701) -> dpkt.ip.IP:
    return _ipv4(
        "192.0.2.1",
        "192.0.2.2",
        _udp(54321, dport, payload),
        dpkt.ip.IP_PROTO_UDP,
    )


class TestL2tpTunnel(unittest.TestCase):
    def test_l2tpv2_udp_ppp_ipv4(self) -> None:
        inner = _inner_ipv4_udp()
        outer = _outer_udp_l2tp(_l2tpv2_hdr(0x1111, 0x2222, _ppp_ipv4(inner)))
        tlist = E2ETunnelList(outer)
        self.assertEqual(len(tlist.tunnels), 1)
        tun = tlist.tunnels[0]
        self.assertEqual(tun.type, "L2TPv2")
        self.assertEqual(tun.id, (0x1111 << 16) | 0x2222)
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")
        self.assertEqual(inet_dst(tlist.ip), "10.0.0.2")

    def test_l2tpv2_udp_ppp_ipv6(self) -> None:
        inner = _inner_ipv6_udp()
        outer = _outer_udp_l2tp(_l2tpv2_hdr(1, 2, _ppp_ipv6(inner)))
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels[0].type, "L2TPv2")
        self.assertEqual(inet_src(tlist.ip), "2001:db8::1")

    def test_l2tpv2_l_s_o_flags(self) -> None:
        inner = _inner_ipv4_udp()
        flags = (
            0x0002
            | E2ETunnelList.L2TP_L_BIT
            | E2ETunnelList.L2TP_S_BIT
            | E2ETunnelList.L2TP_O_BIT
        )
        payload = _l2tpv2_hdr(9, 10, _ppp_ipv4(inner), flags=flags, offset_size=4)
        tlist = E2ETunnelList(_outer_udp_l2tp(payload))
        self.assertEqual(tlist.tunnels[0].type, "L2TPv2")
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_l2tpv2_offset_overrun_is_miss(self) -> None:
        flags = 0x0002 | E2ETunnelList.L2TP_O_BIT
        payload = struct.pack("!HHHH", flags, 1, 2, 40000) + b"\x00\x00"
        outer = _outer_udp_l2tp(payload)
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "192.0.2.1")

    def test_l2tpv2_truncated_header_is_miss(self) -> None:
        outer = _outer_udp_l2tp(b"\x00\x02\x00")
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "192.0.2.1")

    def test_l2tpv2_ppp_pfc(self) -> None:
        inner = _inner_ipv4_udp()
        outer = _outer_udp_l2tp(_l2tpv2_hdr(3, 4, _ppp_ipv4(inner, compressed=True)))
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels[0].type, "L2TPv2")
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_l2tpv2_lcp_only_keeps_outer_ip(self) -> None:
        lcp = b"\xff\x03\xc0\x21" + b"\x01\x01\x00\x04"
        outer = _outer_udp_l2tp(_l2tpv2_hdr(1, 1, lcp))
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "192.0.2.1")

    def test_l2tpv2_control_keeps_outer_ip(self) -> None:
        flags = 0x0002 | E2ETunnelList.L2TP_T_BIT
        outer = _outer_udp_l2tp(_l2tpv2_hdr(1, 0, b"\x00\x00", flags=flags))
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "192.0.2.1")

    def test_l2tp_udp_garbage_keeps_outer_ip(self) -> None:
        outer = _outer_udp_l2tp(b"not-l2tp-payload!!!!!!")
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "192.0.2.1")

    def test_l2tpv3_udp_ethernet_ipv4(self) -> None:
        inner = _inner_ipv4_udp()
        payload = struct.pack("!I", 0xAABBCCDD) + _ethernet_ipv4(inner)
        tlist = E2ETunnelList(_outer_udp_l2tp(payload))
        self.assertEqual(tlist.tunnels[0].type, "L2TPv3")
        self.assertEqual(tlist.tunnels[0].id, 0xAABBCCDD)
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_l2tpv3_udp_cookie_ethernet(self) -> None:
        inner = _inner_ipv4_udp()
        payload = struct.pack("!I", 99) + b"\x11\x22\x33\x44" + _ethernet_ipv4(inner)
        tlist = E2ETunnelList(_outer_udp_l2tp(payload))
        self.assertEqual(tlist.tunnels[0].type, "L2TPv3")
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_l2tpv3_udp_vlan_ethernet(self) -> None:
        inner = _inner_ipv4_udp()
        payload = struct.pack("!I", 5) + _ethernet_ipv4(inner, vlan=100)
        tlist = E2ETunnelList(_outer_udp_l2tp(payload))
        self.assertEqual(tlist.tunnels[0].type, "L2TPv3")
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_l2tpv3_session_id_looks_like_v2(self) -> None:
        inner = _inner_ipv4_udp()
        payload = struct.pack("!I", 0x00020000) + _ethernet_ipv4(inner)
        tlist = E2ETunnelList(_outer_udp_l2tp(payload))
        self.assertEqual(tlist.tunnels[0].type, "L2TPv3")
        self.assertEqual(tlist.tunnels[0].id, 0x00020000)
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_l2tpv3_over_ip_proto_115_ppp(self) -> None:
        inner = _inner_ipv4_udp()
        payload = struct.pack("!I", 7) + _ppp_ipv4(inner)
        outer = _ipv4("192.0.2.1", "192.0.2.2", payload, E2ETunnelList.IP_PROTO_L2TP)
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels[0].type, "L2TPv3")
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_l2tpv3_over_ip_raw_ip(self) -> None:
        inner = _inner_ipv4_udp()
        payload = struct.pack("!I", 8) + bytes(inner)
        outer = _ipv4("192.0.2.1", "192.0.2.2", payload, E2ETunnelList.IP_PROTO_L2TP)
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels[0].type, "L2TPv3")
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_l2tpv3_over_ip_control_miss(self) -> None:
        flags = 0x0003 | E2ETunnelList.L2TP_T_BIT
        payload = struct.pack("!HHI", flags, 12, 0) + b"\x00" * 8
        outer = _ipv4("192.0.2.1", "192.0.2.2", payload, E2ETunnelList.IP_PROTO_L2TP)
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "192.0.2.1")

    def test_l2tpv3_session_id_zero_miss(self) -> None:
        inner = _inner_ipv4_udp()
        payload = struct.pack("!I", 0) + _ethernet_ipv4(inner)
        tlist = E2ETunnelList(_outer_udp_l2tp(payload))
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "192.0.2.1")

    def test_l2tpv2_ipv6_outer(self) -> None:
        inner = _inner_ipv4_udp()
        udp = _udp(40000, 1701, _l2tpv2_hdr(1, 2, _ppp_ipv4(inner)))
        outer = _ipv6("2001:db8::a", "2001:db8::b", udp, dpkt.ip.IP_PROTO_UDP)
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels[0].type, "L2TPv2")
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_l2tp_e2epacket_inner_transport(self) -> None:
        inner = _inner_ipv4_udp(sport=4000, dport=80)
        outer = _outer_udp_l2tp(_l2tpv2_hdr(1, 2, _ppp_ipv4(inner)))
        pkt = E2EPacket(
            num=1,
            utc_date_time=datetime.datetime.now(datetime.timezone.utc),
            eth=None,
            outerip=outer,
            transport_port_cb=E2EConfig().get_transport_port_cb(),
        )
        self.assertEqual(pkt.ip_src, "10.0.0.1")
        self.assertEqual(pkt.transport_src_port, 4000)
        self.assertEqual(pkt.transport_dst_port, 80)
        self.assertNotEqual(pkt.transport_src_port, 1701)
        self.assertNotEqual(pkt.transport_dst_port, 1701)
        self.assertIsNotNone(pkt.tunnel)


def inet_src(ipkt: Optional[dpkt.Packet]) -> str:
    assert ipkt is not None
    return socket.inet_ntop(
        socket.AF_INET if isinstance(ipkt, dpkt.ip.IP) else socket.AF_INET6,
        getattr(ipkt, "src"),
    )


def inet_dst(ipkt: Optional[dpkt.Packet]) -> str:
    assert ipkt is not None
    return socket.inet_ntop(
        socket.AF_INET if isinstance(ipkt, dpkt.ip.IP) else socket.AF_INET6,
        getattr(ipkt, "dst"),
    )


if __name__ == "__main__":
    unittest.main()
