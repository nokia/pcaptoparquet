import datetime
import unittest
from unittest.mock import MagicMock

import dpkt

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

        # Verify flags
        self.assertTrue(packet.transport_syn_flag)
        self.assertTrue(packet.transport_ack_flag)
        self.assertFalse(packet.transport_fin_flag)


if __name__ == "__main__":
    unittest.main()
