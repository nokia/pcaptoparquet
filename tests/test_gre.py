# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""Unit tests for experimental GRE tunnel unwrapping."""

import datetime
import struct
import unittest

import dpkt

from pcaptoparquet import E2EConfig
from pcaptoparquet.e2e_packet import E2EPacket
from pcaptoparquet.e2e_tunnel import E2ETunnelList

from .test_l2tp import (
    _inner_ipv4_udp,
    _inner_ipv6_udp,
    _ipv4,
    _ipv6,
    _l2tpv2_hdr,
    _ppp_ipv4,
    _udp,
    inet_src,
)


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


def _gre_v0(
    proto: int,
    payload: bytes,
    key: int | None = None,
    checksum: bool = False,
    seq: int | None = None,
    routing: bool = False,
) -> bytes:
    flags = 0
    if routing:
        flags |= E2ETunnelList.GRE_R_BIT
    if checksum:
        flags |= E2ETunnelList.GRE_C_BIT
    if key is not None:
        flags |= E2ETunnelList.GRE_K_BIT
    if seq is not None:
        flags |= E2ETunnelList.GRE_S_BIT
    buf = struct.pack("!HH", flags, proto)
    if checksum:
        buf += b"\x00\x00\x00\x00"
    if key is not None:
        buf += struct.pack("!I", key)
    if seq is not None:
        buf += struct.pack("!I", seq)
    return buf + payload


def _outer_gre(gre: bytes) -> dpkt.ip.IP:
    return _ipv4("198.51.100.1", "198.51.100.2", gre, E2ETunnelList.IP_PROTO_GRE)


class TestGreTunnel(unittest.TestCase):
    def test_gre_v0_ipv4(self) -> None:
        inner = _inner_ipv4_udp()
        tlist = E2ETunnelList(_outer_gre(_gre_v0(0x0800, bytes(inner))))
        self.assertEqual(len(tlist.tunnels), 1)
        self.assertEqual(tlist.tunnels[0].type, "GRE")
        self.assertEqual(tlist.tunnels[0].id, 0)
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_gre_v0_ipv6(self) -> None:
        inner = _inner_ipv6_udp()
        tlist = E2ETunnelList(_outer_gre(_gre_v0(0x86DD, bytes(inner))))
        self.assertEqual(tlist.tunnels[0].type, "GRE")
        self.assertEqual(inet_src(tlist.ip), "2001:db8::1")

    def test_gre_v0_key(self) -> None:
        inner = _inner_ipv4_udp()
        tlist = E2ETunnelList(_outer_gre(_gre_v0(0x0800, bytes(inner), key=0xDEADBEEF)))
        self.assertEqual(tlist.tunnels[0].id, 0xDEADBEEF)
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_gre_v0_checksum_and_seq(self) -> None:
        inner = _inner_ipv4_udp()
        gre = _gre_v0(0x0800, bytes(inner), checksum=True, seq=9)
        tlist = E2ETunnelList(_outer_gre(gre))
        self.assertEqual(tlist.tunnels[0].type, "GRE")
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_gre_ethernet_bridging(self) -> None:
        inner = _inner_ipv4_udp()
        gre = _gre_v0(E2ETunnelList.ETH_TYPE_TEB, _ethernet_ipv4(inner))
        tlist = E2ETunnelList(_outer_gre(gre))
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_gre_ethernet_vlan(self) -> None:
        inner = _inner_ipv4_udp()
        gre = _gre_v0(E2ETunnelList.ETH_TYPE_TEB, _ethernet_ipv4(inner, vlan=20))
        tlist = E2ETunnelList(_outer_gre(gre))
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_gre_proto_ipv4_number(self) -> None:
        inner = _inner_ipv4_udp()
        tlist = E2ETunnelList(_outer_gre(_gre_v0(0x0004, bytes(inner))))
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_gre_pptp_v1_ppp_ipv4(self) -> None:
        inner = _inner_ipv4_udp()
        ppp = _ppp_ipv4(inner)
        gre = struct.pack("!HHHH", 0x0001, 0x880B, len(ppp), 0x1234) + ppp
        tlist = E2ETunnelList(_outer_gre(gre))
        self.assertEqual(tlist.tunnels[0].type, "GRE")
        self.assertEqual(tlist.tunnels[0].id, 0x1234)
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_gre_pptp_v1_lcp_miss(self) -> None:
        lcp = b"\xff\x03\xc0\x21\x01\x01\x00\x04"
        gre = struct.pack("!HHHH", 0x0001, 0x880B, len(lcp), 0x1234) + lcp
        outer = _outer_gre(gre)
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "198.51.100.1")

    def test_gre_r_bit_miss(self) -> None:
        inner = _inner_ipv4_udp()
        gre = _gre_v0(0x0800, bytes(inner), routing=True)
        outer = _outer_gre(gre)
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "198.51.100.1")

    def test_gre_truncated_miss(self) -> None:
        outer = _outer_gre(b"\x00\x00")
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "198.51.100.1")

    def test_gre_erspan_miss(self) -> None:
        gre = _gre_v0(E2ETunnelList.ETH_TYPE_ERSPAN, b"\x00" * 20)
        outer = _outer_gre(gre)
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels, [])
        self.assertEqual(inet_src(tlist.ip), "198.51.100.1")

    def test_gre_ipv6_outer(self) -> None:
        inner = _inner_ipv4_udp()
        gre = _gre_v0(0x0800, bytes(inner))
        outer = _ipv6("2001:db8::1", "2001:db8::2", gre, E2ETunnelList.IP_PROTO_GRE)
        tlist = E2ETunnelList(outer)
        self.assertEqual(tlist.tunnels[0].type, "GRE")
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_gre_then_l2tpv2_nested(self) -> None:
        inner = _inner_ipv4_udp()
        l2tp = _l2tpv2_hdr(0x10, 0x20, _ppp_ipv4(inner))
        mid = _ipv4("203.0.113.1", "203.0.113.2", _udp(40000, 1701, l2tp), 17)
        gre = _gre_v0(0x0800, bytes(mid))
        tlist = E2ETunnelList(_outer_gre(gre))
        self.assertEqual([t.type for t in tlist.tunnels], ["GRE", "L2TPv2"])
        self.assertEqual(tlist.tunnels[1].id, (0x10 << 16) | 0x20)
        self.assertEqual(inet_src(tlist.ip), "10.0.0.1")

    def test_gre_e2epacket_inner_transport(self) -> None:
        inner = _inner_ipv4_udp(sport=5000, dport=443)
        outer = _outer_gre(_gre_v0(0x0800, bytes(inner)))
        pkt = E2EPacket(
            num=1,
            utc_date_time=datetime.datetime.now(datetime.timezone.utc),
            eth=None,
            outerip=outer,
            transport_port_cb=E2EConfig().get_transport_port_cb(),
        )
        self.assertEqual(pkt.ip_src, "10.0.0.1")
        self.assertEqual(pkt.transport_src_port, 5000)
        self.assertEqual(pkt.transport_dst_port, 443)
        self.assertIsNotNone(pkt.tunnel)


if __name__ == "__main__":
    unittest.main()
