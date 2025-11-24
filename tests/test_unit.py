import datetime
import unittest
from unittest.mock import MagicMock

import dpkt

from pcaptoparquet.e2e_packet import E2EPacket


class TestE2EPacket(unittest.TestCase):
    def setUp(self) -> None:
        self.packet = E2EPacket(
            num=1,
            utc_date_time=datetime.datetime.now(datetime.timezone.utc),
            eth=None,
            outerip=None,
            transport_port_cb={},
        )

    def test_validate_str(self) -> None:
        self.assertEqual(E2EPacket.validate_str("hello|world"), "hello\\x7cworld")
        self.assertEqual(E2EPacket.validate_str("hello world"), "hello world")

    def test_header(self) -> None:
        header = E2EPacket.header()
        self.assertTrue(header.startswith("num|utc_date_time"))
        self.assertIn("eth_src", header)

    def test_get_dtypes(self) -> None:
        dtypes = E2EPacket.get_dtypes()
        self.assertEqual(dtypes["num"], "UInt32")
        self.assertEqual(dtypes["utc_date_time"], "datetime64[ns, UTC]")

    def test_create_empty_attr(self) -> None:
        self.packet.create_empty_attr()
        self.assertIsNone(self.packet.eth_src)
        self.assertIsNone(self.packet.ip_src)

    def test_get_category_str_value(self) -> None:
        self.assertEqual(E2EPacket.get_category_str_value("test", "any"), "test")
        self.assertEqual(E2EPacket.get_category_str_value(None, "eth_vlan_tags"), "[]")
        self.assertEqual(E2EPacket.get_category_str_value(None, "other"), "")

    def test_decode_eth(self) -> None:
        eth = MagicMock(spec=dpkt.ethernet.Ethernet)
        eth.src = b"\x00\x11\x22\x33\x44\x55"
        eth.dst = b"\x66\x77\x88\x99\xaa\xbb"
        eth.data = MagicMock(spec=dpkt.ip.IP)

        outerip = self.packet.decode_eth(eth)

        self.assertEqual(self.packet.eth_src, "00:11:22:33:44:55")
        self.assertEqual(self.packet.eth_dst, "66:77:88:99:aa:bb")
        self.assertIsNotNone(outerip)


if __name__ == "__main__":
    unittest.main()
