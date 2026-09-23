import datetime
import socket
import struct
import unittest
from typing import Any, Optional
from unittest.mock import MagicMock

import dpkt

from pcaptoparquet import e2e_ping
from pcaptoparquet.e2e_config import E2EConfig, ProtocolDecoder
from pcaptoparquet.e2e_packet import E2EPacket


class TestE2EPacket(unittest.TestCase):
    """
    Unit tests for E2EPacket class
    """

    def setUp(self) -> None:
        self.packet = E2EPacket(
            num=1,
            utc_date_time=datetime.datetime.now(datetime.timezone.utc),
            eth=None,
            outerip=None,
            transport_port_cb={},
        )

    def test_validate_str(self) -> None:
        """
        Test string validation method
        """
        self.assertEqual(E2EPacket.validate_str("hello|world"), "hello\\x7cworld")
        self.assertEqual(E2EPacket.validate_str("hello world"), "hello world")

    def test_header(self) -> None:
        """
        Test header method
        """
        header = E2EPacket.header()
        self.assertTrue(header.startswith("num|utc_date_time"))
        self.assertIn("eth_src", header)

    def test_get_dtypes(self) -> None:
        """
        Test get_dtypes method
        """
        dtypes = E2EPacket.get_dtypes()
        self.assertEqual(dtypes["num"], "UInt32")
        self.assertEqual(dtypes["utc_date_time"], "datetime64[ns, UTC]")

    def test_parquet_columns_match_schema_prefix(self) -> None:
        """MCP catalog columns come from E2EPacket, not a second list."""
        self.assertEqual(E2EPacket.prefix_columns(), ("num", "utc_date_time"))
        columns = E2EPacket.parquet_columns()
        self.assertEqual(columns[:2], ("num", "utc_date_time"))
        self.assertIn("eth_src", columns)
        self.assertIn("app_response", columns)
        self.assertNotIn("error", columns)
        self.assertNotIn("error_message", columns)

    def test_create_empty_attr(self) -> None:
        """
        Test create_empty_attr method
        """
        self.packet.create_empty_attr()
        self.assertIsNone(self.packet.eth_src)
        self.assertIsNone(self.packet.ip_src)

    def test_get_category_str_value(self) -> None:
        """
        Test get_category_str_value method
        """
        self.assertEqual(E2EPacket.get_category_str_value("test", "any"), "test")
        self.assertEqual(E2EPacket.get_category_str_value(None, "eth_vlan_tags"), "[]")
        self.assertEqual(E2EPacket.get_category_str_value(None, "other"), "")

    def test_decode_eth(self) -> None:
        """
        Test decode_eth method
        """
        eth = MagicMock(spec=dpkt.ethernet.Ethernet)
        eth.src = b"\x00\x11\x22\x33\x44\x55"
        eth.dst = b"\x66\x77\x88\x99\xaa\xbb"
        eth.data = MagicMock(spec=dpkt.ip.IP)

        outerip = self.packet.decode_eth(eth)

        self.assertEqual(self.packet.eth_src, "00:11:22:33:44:55")
        self.assertEqual(self.packet.eth_dst, "66:77:88:99:aa:bb")
        self.assertIsNotNone(outerip)

    def test_app_session_field_initialization(self) -> None:
        """
        Test that app_session field is properly initialized and present in metadata
        """
        # Verify app_session is present in dtypes metadata
        dtypes = E2EPacket.get_dtypes()
        self.assertIn("app_session", dtypes)
        self.assertEqual(dtypes["app_session"], "category")

        # Verify app_session is initialized to None in setUp packet
        self.assertIsNone(self.packet.app_session)

        # Verify app_session is initialized to None in new packet
        packet = E2EPacket(
            num=1,
            utc_date_time=datetime.datetime.now(datetime.timezone.utc),
            eth=None,
            outerip=None,
            transport_port_cb={},
        )
        self.assertIsNone(packet.app_session)

    def test_decode_tcp_sackok(self) -> None:
        """
        Test TCP SACK OK option decoding
        """
        # Create a mock TCP packet with SACK OK option
        tcp = MagicMock(spec=dpkt.tcp.TCP)
        tcp.sport = 80
        tcp.dport = 12345
        tcp.seq = 1000
        tcp.ack = 2000
        tcp.win = 65535
        tcp.flags = dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK
        tcp.__hdr_len__ = 20
        tcp.data = b""
        # TCP option: SACK OK (kind=4, length=2)
        tcp.opts = b"\x04\x02"

        # Create packet with IP layer set
        packet = E2EPacket(
            num=1,
            utc_date_time=datetime.datetime.now(datetime.timezone.utc),
            eth=None,
            outerip=None,
            transport_port_cb={},
        )
        packet.ip_len = 40  # IP header (20) + TCP header (20)

        # Decode TCP header
        packet.decode_tcp_header(tcp)

        # Verify basic TCP fields
        self.assertEqual(packet.transport_type, "TCP")
        self.assertEqual(packet.transport_src_port, 80)
        self.assertEqual(packet.transport_dst_port, 12345)
        self.assertEqual(packet.transport_seq, 1000)
        self.assertEqual(packet.transport_ack, 2000)
        self.assertEqual(packet.transport_win, 65535)

        # Verify SACK OK was decoded
        self.assertTrue(packet.transport_sackok)
        self.assertTrue(packet.transport_syn_flag)
        self.assertTrue(packet.transport_ack_flag)
        self.assertFalse(packet.transport_fin_flag)

    def test_decode_sack_wire_order(self) -> None:
        """SACK blocks follow RFC 2018 left-to-right wire order."""
        packet = E2EPacket(
            num=1,
            utc_date_time=datetime.datetime.now(datetime.timezone.utc),
            eth=None,
            outerip=None,
            transport_port_cb={},
        )
        one = struct.pack("!II", 10, 20)
        self.assertEqual(packet.decode_sack(one), (10, 20, None, None, None, None))
        two = struct.pack("!IIII", 10, 20, 30, 40)
        self.assertEqual(packet.decode_sack(two), (10, 20, 30, 40, None, None))
        three = struct.pack("!IIIIII", 10, 20, 30, 40, 50, 60)
        self.assertEqual(packet.decode_sack(three), (10, 20, 30, 40, 50, 60))

    def test_icmp6_echo_is_ping(self) -> None:
        """ICMPv6 echo request and reply are labeled PING."""
        cb = E2EConfig().get_transport_port_cb()
        request = self._packet_from_eth(self._icmp6_echo(128, 0x1234, 7), cb)
        self.assertEqual(request.transport_type, "ICMP6")
        self.assertEqual(request.app_type, "PING")
        self.assertEqual(request.app_session, 0x1234)
        self.assertEqual(request.app_seq, 7)
        self.assertEqual(request.transport_cid, 0x1234)
        self.assertEqual(request.transport_pkn, 7)
        self.assertEqual(request.app_request, f"ECHO REQUEST {request.ip_len} bytes.")
        self.assertIsNone(request.app_response)

        reply = self._packet_from_eth(self._icmp6_echo(129, 0x1234, 7), cb)
        self.assertEqual(reply.transport_type, "ICMP6")
        self.assertEqual(reply.app_type, "PING")
        self.assertEqual(reply.app_response, f"ECHO REPLY {reply.ip_len} bytes.")
        self.assertIsNone(reply.app_request)

        self.assertIsNot(cb["ICMP"], cb["ICMP6"])
        self.assertIs(cb["ICMP"].decode, e2e_ping.decode)
        self.assertIs(cb["ICMP6"].decode, e2e_ping.decode)

        def skip_decode(_packet: Any, _transport: Any, _app: Any) -> Optional[bytes]:
            return None

        cb["ICMP6"] = ProtocolDecoder(skip_decode)
        skipped = self._packet_from_eth(self._icmp6_echo(128, 0x1234, 7), cb)
        self.assertEqual(skipped.transport_type, "ICMP6")
        self.assertIsNone(skipped.app_type)
        self.assertIs(cb["ICMP"].decode, e2e_ping.decode)

    @staticmethod
    def _icmp6_echo(icmp_type: int, ident: int, seq: int) -> dpkt.ethernet.Ethernet:
        echo = dpkt.icmp6.ICMP6.Echo(id=ident, seq=seq, data=b"abcdefgh")
        icmp6 = dpkt.icmp6.ICMP6(type=icmp_type, code=0, data=echo)
        ip6 = dpkt.ip6.IP6(
            src=socket.inet_pton(socket.AF_INET6, "2001:db8::1"),
            dst=socket.inet_pton(socket.AF_INET6, "2001:db8::2"),
            nxt=dpkt.ip.IP_PROTO_ICMP6,
            hlim=64,
            data=icmp6,
        )
        eth = dpkt.ethernet.Ethernet(
            src=b"\x00\x11\x22\x33\x44\x55",
            dst=b"\x66\x77\x88\x99\xaa\xbb",
            type=dpkt.ethernet.ETH_TYPE_IP6,
            data=ip6,
        )
        return dpkt.ethernet.Ethernet(bytes(eth))

    @staticmethod
    def _packet_from_eth(
        eth: dpkt.ethernet.Ethernet, transport_port_cb: dict[str, object]
    ) -> E2EPacket:
        return E2EPacket(
            num=1,
            utc_date_time=datetime.datetime.now(datetime.timezone.utc),
            eth=eth,
            outerip=None,
            transport_port_cb=transport_port_cb,
        )


if __name__ == "__main__":
    unittest.main()
