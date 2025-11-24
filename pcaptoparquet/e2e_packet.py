# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""
This module defines the E2EPacket class, which represents a packet in an end-to-end
communication.
Use DPKT to extract E2E relevant contents from packets such as:
    * User Tags
    * Collection Type (Client, Network, Server)
    * Timestamp
    * Encapsulation
    * Snaplen
    * Ethernet
        - Type
        - Source
        - Destination
        - VLAN1
        - VLAN2
        - PBits
    * Tunnel
        - Type
        - Source
        - Destination
        - Overhead
    * IP
        - Version
        - Source
        - Destination
        - QoS
        - ID
    * ESP
        - SPI
        - Seq
    * Transport
        - Type (UDP, TCP , QUIC)
        - Source
        - Destination
        - Flags
            + SYN
            + ACK
            + FIN
            + RST
            + ECN
            + PSH
        - CID
        - MSS
        - PKN
        - SEQ
        - ACK
        - WIN
        - SACK
        - TSVAL
        - TSECR
        - SPIN
        - CID
        - PKN
        - Stream
    * Security
        - SessionID
        - ServerName
        - Handshake
    * Application
        - Type (ICMP, DNS, HTTP, QUIC)
        - Method
        - Referer
        - ServerNames
        - ServerAddress
"""
import datetime
import struct
from typing import Any, Optional, Union

import dpkt
from dpkt.utils import inet_to_str, mac_to_str

from .e2e_tunnel import E2ETunnelList


class E2EPacket:
    """
    Class that represents a packet in an end-to-end communication.
    """

    _prefix_meta = {
        # Packet metadata: check __str__ method
        "num": "UInt32",
        "utc_date_time": "datetime64[ns, UTC]",
    }
    _decoder_meta = {
        # Link Layer Fields and types
        "eth_src": "category",
        "eth_dst": "category",
        "eth_vlan_tags": "string",
        "eth_mpls_labels": "string",
        "tunnel": "string",
        # Network Layer Fields and types
        "ip_version": "category",
        "ip_src": "category",
        "ip_dst": "category",
        "ip_dscp": "category",
        "ip_ecn": "category",
        "ip_id": "UInt16",
        "ip_ttl": "UInt8",
        "ip_len": "UInt16",
        "ip_frag": "boolean",
        "esp_spi": "UInt32",
        "esp_seq": "UInt32",
        # Transport Layer Fields and types
        "transport_type": "category",
        "transport_header_len": "UInt16",
        "transport_options_len": "UInt16",
        "transport_data_len": "UInt16",
        "transport_capture_len": "UInt16",
        "transport_src_port": "UInt16",
        "transport_dst_port": "UInt16",
        "transport_fin_flag": "boolean",
        "transport_syn_flag": "boolean",
        "transport_rst_flag": "boolean",
        "transport_push_flag": "boolean",
        "transport_ack_flag": "boolean",
        "transport_urg_flag": "boolean",
        "transport_ece_flag": "boolean",
        "transport_cwr_flag": "boolean",
        "transport_ns_flag": "boolean",
        "transport_seq": "UInt32",
        "transport_ack": "UInt32",
        "transport_win": "UInt16",
        "transport_mss": "UInt16",
        "transport_wscale": "UInt16",
        "transport_sackok": "boolean",
        "transport_sack_1_from": "UInt32",
        "transport_sack_1_to": "UInt32",
        "transport_sack_2_from": "UInt32",
        "transport_sack_2_to": "UInt32",
        "transport_sack_3_from": "UInt32",
        "transport_sack_3_to": "UInt32",
        "transport_tsval": "UInt32",
        "transport_tsecr": "UInt32",
        "transport_spin": "boolean",
        "transport_cid": "UInt64",
        "transport_pkn": "UInt64",
        # Application Layer Fields and types
        "e2e_sni": "string",
        "app_type": "category",
        "app_session": "category",
        "app_seq": "UInt64",
        "app_request": "string",
        "app_response": "string",
        "error": "boolean",
        "error_message": "string",
    }

    _not_decoded_data: Any = None

    SEPARATOR = "|"
    HEX_SEPARATOR = r"\x7c"

    @classmethod
    def validate_str(cls, value: str) -> str:
        """
        Validate a string value by replacing the separator with its hex representation.

        Args:
            value (str): The string value to validate.

        Returns:
            str: The validated string.
        """
        return value.replace(cls.SEPARATOR, cls.HEX_SEPARATOR)

    @classmethod
    def header(cls, meta_list: tuple[dict[str, str], dict[str, str]] = ({}, {})) -> str:
        """
        Returns the header of the packet as a string.

        Args:
            meta_list (tuple, optional): A tuple containing user metadata and
                PCAP metadata. Defaults to ({}, {}).

        Returns:
            str: The header string.
        """
        hdrmeta = list(cls._prefix_meta.keys())
        for meta in meta_list:
            hdrmeta.extend(meta.keys())
        hdrmeta.extend(cls._decoder_meta.keys())
        out = hdrmeta[0]
        for field_name in hdrmeta[1:]:
            out = out + cls.SEPARATOR + field_name
        return out

    @classmethod
    def get_dtypes(
        cls, meta_list: tuple[dict[str, str], dict[str, str]] = ({}, {})
    ) -> dict[str, str]:
        """
        Returns the dtypes of the packet as a dictionary.

        Args:
            meta_list (tuple, optional): A tuple containing user metadata and
                PCAP metadata. Defaults to ({}, {}).

        Returns:
            dict[str, str]: A dictionary mapping field names to their data types.
        """
        dtypes = {}
        for field_name, field_type in cls._prefix_meta.items():
            dtypes[field_name] = field_type
        for meta in meta_list:
            for field_name, field_type in meta.items():
                dtypes[field_name] = field_type
        for field_name, field_type in cls._decoder_meta.items():
            dtypes[field_name] = field_type
        return dtypes

    def __str__(self) -> str:
        """
        Returns the packet as a string representation.

        Returns:
            str: The string representation of the packet.

        Raises:
            ValueError: If the prefix metadata is unknown.
        """
        # This is hardcoded...
        if (
            list(self._prefix_meta.keys())[0] == "num"
            and list(self._prefix_meta.keys())[1] == "utc_date_time"
        ):
            out = (
                str(self.num)
                + self.SEPARATOR
                + str(self.utc_date_time.strftime("%Y-%m-%d %H:%M:%S.%f"))
            )
        else:
            raise ValueError("Unknown prefix metadata")

        for field_name in self.meta_values:
            out = out + self.SEPARATOR
            if getattr(self, field_name):
                out = out + self.validate_str(str(getattr(self, field_name)))

        hdrmeta = list(self._decoder_meta.keys())
        for field_name in hdrmeta:
            out = out + self.SEPARATOR
            if getattr(self, field_name):
                out = out + self.validate_str(str(getattr(self, field_name)))
        return out

    def get_not_decoded_data(self) -> Any:
        """
        Returns the data that was not decoded.

        Returns:
            Any: The not decoded data.
        """
        return self._not_decoded_data

    @staticmethod
    def get_obj_list(listobj: list[Any]) -> list[Any]:
        """
        Convert a list of objects to a list of dictionaries or values.

        Args:
            listobj (list[Any]): The list of objects to convert.

        Returns:
            list[Any]: The converted list.
        """
        obj_list = []
        if isinstance(listobj[0], dpkt.ethernet.MPLSlabel):
            # val=104275, exp=2, s=1, ttl=251
            for label in listobj:
                obj_list.append(
                    {
                        "val": label.val,
                        "exp": label.exp,
                        "s": label.s,
                        "ttl": label.ttl,
                    }
                )
        elif isinstance(listobj[0], dpkt.ethernet.VLANtag8021Q):
            # self.id, self.pri, self.cfi, self.type
            for tag in listobj:
                obj_list.append(
                    {
                        "id": tag.id,
                        "pri": tag.pri,
                        "cfi": tag.cfi,
                        "type": tag.type,
                    }
                )
        else:
            obj_list = listobj
        return obj_list

    @staticmethod
    def get_category_str_value(obj: Any, name: str) -> str:
        """
        Get the string representation of a category value.

        Args:
            obj (Any): The object to convert.
            name (str): The name of the field.

        Returns:
            str: The string representation.
        """
        if obj is not None:
            if isinstance(obj, list):
                value = str(E2EPacket.get_obj_list(obj))
            else:
                value = str(obj)
        else:
            if name in ["eth_vlan_tags", "eth_mpls_labels", "tunnel"]:
                value = "[]"
            else:
                value = ""
        return value

    # def to_dict(self, dtypes: Optional[dict[str, str]] = None) -> dict[str, Any]:
    def to_dict(self, dtypes: dict[str, str]) -> dict[str, Any]:
        """
        Convert the packet to a dictionary based on the provided data types.

        Args:
            dtypes (dict[str, str]): A dictionary mapping field names to their
                data types.

        Returns:
            dict[str, Any]: The packet as a dictionary.
        """
        pkt_dict = dict[str, Any]()
        for field_name, field_type in dtypes.items():
            obj = getattr(self, field_name)
            if field_type in ["category", "string"]:
                pkt_dict[field_name] = E2EPacket.get_category_str_value(obj, field_name)
            elif field_type in [
                "datetime64[ns, UTC]",
                "UInt8",
                "UInt16",
                "UInt32",
                "UInt64",
            ]:
                pkt_dict[field_name] = obj
            elif field_type == "boolean":
                if obj is not None:
                    pkt_dict[field_name] = bool(obj)
                else:
                    pkt_dict[field_name] = False
            else:  # field_type== "object":
                if obj is not None:
                    pkt_dict[field_name] = str(obj)
                else:
                    pkt_dict[field_name] = ""

        return pkt_dict

    def to_json(self, d_: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        """
        Convert the packet to a JSON-compatible dictionary.

        Args:
            d_ (dict[str, Any], optional): An existing dictionary to populate.
                Defaults to None.

        Returns:
            dict[str, Any]: The JSON-compatible dictionary.

        Raises:
            ValueError: If the prefix metadata is unknown.
        """
        if d_ is None:
            d_ = {}

        # This hardcoded...
        if (
            list(self._prefix_meta.keys())[0] == "num"
            and list(self._prefix_meta.keys())[1] == "utc_date_time"
        ):
            d_["num"] = str(self.num)
            d_["utc_date_time"] = str(
                self.utc_date_time.strftime("%Y-%m-%d %H:%M:%S.%f")
            )
        else:
            raise ValueError("Unknown prefix metadata")

        hdrmeta = list(self._decoder_meta.keys())
        for field_name in hdrmeta:
            obj = getattr(self, field_name)
            if obj is not None:
                if hasattr(obj, "toJSON"):
                    d_[field_name] = obj.toJSON()
                else:
                    d_[field_name] = obj
                    if isinstance(obj, list):
                        d_[field_name] = E2EPacket.get_obj_list(obj)
        return d_

    def create_empty_attr(self) -> None:
        """
        Initialize all fields in the E2EPacket class with None.
        """
        for field_name, _ in self._decoder_meta.items():
            setattr(self, field_name, None)

    def decode_eth(
        self, eth: dpkt.ethernet.Ethernet
    ) -> Optional[Union[dpkt.ip.IP, dpkt.ip6.IP6]]:
        """
        Decode an Ethernet packet and extract relevant information.

        Args:
            eth (dpkt.ethernet.Ethernet): The Ethernet packet to decode.

        Returns:
            Optional[Union[dpkt.ip.IP, dpkt.ip6.IP6]]: The outer IP packet if found,
                otherwise None.
        """
        # Source and Destination MAC addresses
        self.eth_src = mac_to_str(getattr(eth, "src"))
        self.eth_dst = mac_to_str(getattr(eth, "dst"))

        # VLAN tags
        try:
            self.eth_vlan_tags = getattr(eth, "vlan_tags")
        except AttributeError:
            self.eth_vlan_tags = None

        # MPLS labels
        try:
            self.eth_mpls_labels = getattr(eth, "mpls_labels")
        except AttributeError:
            self.eth_mpls_labels = None

        outerip = eth.data

        while outerip and not isinstance(outerip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            try:
                outerip = getattr(outerip, "data")
            except AttributeError:
                outerip = None

        if isinstance(outerip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return outerip

        return None

    def decode_tunnels(
        self, outerip: Union[dpkt.ip.IP, dpkt.ip6.IP6]
    ) -> Optional[Union[dpkt.ip.IP, dpkt.ip6.IP6]]:
        """
        Decode tunnels within the outer IP packet.

        Args:
            outerip (Union[dpkt.ip.IP, dpkt.ip6.IP6]): The outer IP packet.

        Returns:
            Optional[Union[dpkt.ip.IP, dpkt.ip6.IP6]]: The inner IP packet if found,
                otherwise None.
        """
        # Tunnel

        try:
            tlist = E2ETunnelList(outerip)
            if len(tlist.tunnels) > 0:
                innerip = tlist.ip
                self.tunnel = tlist
            else:
                innerip = outerip
        except AttributeError:
            innerip = outerip

        if isinstance(innerip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return innerip

        return None

    def decode_esp(
        self, esp: dpkt.esp.ESP
    ) -> Optional[Union[dpkt.tcp.TCP, dpkt.udp.UDP]]:
        """
        Decode the ESP (Encapsulating Security Payload) packet.

        Args:
            esp (dpkt.esp.ESP): The ESP packet.

        Returns:
            Optional[Union[dpkt.tcp.TCP, dpkt.udp.UDP]]: The transport layer packet
                if decoded, otherwise None.
        """
        transport = None
        self.esp_spi = getattr(esp, "spi")
        self.esp_seq = getattr(esp, "seq")
        if (len(esp.data) + 8) == self.ip_len:
            offsets = [24, 16, 12]
            while (transport is None) and offsets:
                offset = offsets.pop()
                proto = esp.data[len(esp.data) - offset - 1 : len(esp.data) - offset]
                if proto == b"\x06":
                    try:
                        transport = dpkt.tcp.TCP(esp.data)
                    except (dpkt.UnpackError, struct.error):
                        transport = None
                elif proto == b"\x11":
                    try:
                        transport = dpkt.udp.UDP(esp.data)
                    except (dpkt.UnpackError, struct.error):
                        transport = None
                    # Check this code below...
                    # try:
                    #     udp = dpkt.udp.UDP(esp.data)
                    #     if (
                    #         (udp.ulen < self.ip_len) and
                    #         (self.ip_len - udp.ulen) < 100
                    #     ):
                    #         transport = udp
                    # except dpkt.UnpackError:
                    #     transport = None

        if transport is None:
            try:
                udp = dpkt.udp.UDP(esp.data)
                if (getattr(udp, "ulen") < self.ip_len) and (
                    self.ip_len - getattr(udp, "ulen")
                ) < 100:
                    transport = udp
            except (dpkt.UnpackError, struct.error):
                transport = None

        if transport is None:
            try:
                transport = dpkt.tcp.TCP(esp.data)
            except (dpkt.UnpackError, struct.error):
                transport = None

        return transport

    def decode_ip_header(
        self, innerip: Union[dpkt.ip.IP, dpkt.ip6.IP6]
    ) -> Optional[Any]:
        """
        Decode the IP header and extract relevant information.

        Args:
            innerip (Union[dpkt.ip.IP, dpkt.ip6.IP6]): The inner IP packet.

        Returns:
            Optional[Any]: The transport layer packet (dpkt object) if found.
        """
        # IP
        # - Version
        if getattr(innerip, "v") == 4:
            self.ip_version = "IPv4"
        else:
            self.ip_version = "IPv6"

        # - Source
        self.ip_src = inet_to_str(getattr(innerip, "src"))
        # - Destination
        self.ip_dst = inet_to_str(getattr(innerip, "dst"))

        # - ID
        self.ip_id = E2ETunnelList.decode_id(innerip)
        # - IP TTL
        self.ip_ttl = E2ETunnelList.decode_ttl(innerip)
        # - IP Length
        self.ip_len = E2ETunnelList.decode_length(innerip, 20)
        # - QoS
        self.ip_dscp = E2ETunnelList.decode_dscp(innerip)
        # - ECN
        self.ip_ecn = E2ETunnelList.decode_ecn(innerip)
        # - IP Frag
        self.ip_frag = E2ETunnelList.decode_frag(innerip)

        transport = innerip.data

        return transport

    def decode_icmp_header(
        self, transport: Union[dpkt.icmp.ICMP, dpkt.icmp6.ICMP6]
    ) -> Optional[Any]:
        """
        Decode the ICMP header.

        Args:
            transport (Union[dpkt.icmp.ICMP, dpkt.icmp6.ICMP6]): The ICMP packet.

        Returns:
            Optional[Any]: The ICMP data.
        """
        # - Type
        if isinstance(transport, dpkt.icmp.ICMP):
            self.transport_type = "ICMP"
        else:
            self.transport_type = "ICMP6"

        # Transport length
        self.transport_header_len = getattr(transport, "__hdr_len__")
        self.transport_options_len = 0
        self.transport_data_len = len(transport.data)
        self.transport_capture_len = len(transport.data)

        return transport.data

    def decode_sack(self, value: bytes) -> tuple[
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
        Optional[int],
    ]:
        """
        Decode the SACK (Selective Acknowledgment) option.

        Args:
            value (bytes): The SACK option value.

        Returns:
            tuple: A tuple containing the SACK blocks
                (start1, end1, start2, end2, start3, end3).
        """
        try:
            sacks = struct.unpack("!IIIIII", value)
            sack_1_from = sacks[4]
            sack_1_to = sacks[5]
            sack_2_from = sacks[2]
            sack_2_to = sacks[3]
            sack_3_from = sacks[0]
            sack_3_to = sacks[1]
        except struct.error:
            try:
                sacks = struct.unpack("!IIII", value)
                sack_1_from = sacks[2]
                sack_1_to = sacks[3]
                sack_2_from = sacks[0]
                sack_2_to = sacks[1]
            except struct.error:
                try:
                    sacks = struct.unpack("!II", value)
                    sack_1_from = sacks[0]
                    sack_1_to = sacks[1]
                except struct.error:
                    sack_1_from = None
                    sack_1_to = None
                sack_2_from = None
                sack_2_to = None
            sack_3_from = None
            sack_3_to = None

        return (sack_1_from, sack_1_to, sack_2_from, sack_2_to, sack_3_from, sack_3_to)

    def decode_tcp_header(self, transport: dpkt.tcp.TCP) -> Optional[Any]:
        """
        Decode the TCP header.

        Args:
            transport (dpkt.tcp.TCP): The TCP packet.

        Returns:
            Optional[Any]: The TCP data.
        """

        # - Type
        self.transport_type = "TCP"

        # Transport length
        self.transport_header_len = getattr(transport, "__hdr_len__")
        self.transport_options_len = len(transport.opts)
        self.transport_data_len = (
            self.ip_len - self.transport_header_len - self.transport_options_len
        )
        self.transport_capture_len = len(transport.data)
        # - Source Port
        self.transport_src_port = getattr(transport, "sport")
        # - Destination Port
        self.transport_dst_port = getattr(transport, "dport")
        # - Flags
        # end of data
        flags = getattr(transport, "flags")
        self.transport_fin_flag = bool(flags & dpkt.tcp.TH_FIN)
        # synchronize sequence numbers
        self.transport_syn_flag = bool(flags & dpkt.tcp.TH_SYN)
        # reset connection
        self.transport_rst_flag = bool(flags & dpkt.tcp.TH_RST)
        # push
        self.transport_push_flag = bool(flags & dpkt.tcp.TH_PUSH)
        # acknowledgment number set
        self.transport_ack_flag = bool(flags & dpkt.tcp.TH_ACK)
        # urgent pointer set
        self.transport_urg_flag = bool(flags & dpkt.tcp.TH_URG)
        # ECN echo, RFC 3168
        self.transport_ece_flag = bool(flags & dpkt.tcp.TH_ECE)
        # congestion window reduced
        self.transport_cwr_flag = bool(flags & dpkt.tcp.TH_CWR)
        # nonce sum, RFC 3540
        self.transport_ns_flag = bool(flags & dpkt.tcp.TH_NS)
        # - CID
        self.transport_cid = None
        # - PKN
        self.transport_pkn = None
        # - SEQ
        self.transport_seq = getattr(transport, "seq")
        # - ACK
        self.transport_ack = getattr(transport, "ack")
        # - WIN
        self.transport_win = getattr(transport, "win")

        # OPTIONS:
        options = dpkt.tcp.parse_opts(transport.opts)
        for _, option in enumerate(options):
            if option is None:
                continue
            value = option[1]
            if option[0] == dpkt.tcp.TCP_OPT_MSS:
                # maximum segment size
                try:
                    self.transport_mss = struct.unpack("!H", value)[0]
                except (dpkt.UnpackError, struct.error):
                    self.transport_mss = None

            elif option[0] == dpkt.tcp.TCP_OPT_WSCALE:
                # window scale factor, RFC 1072
                try:
                    self.transport_wscale = 2 ** int(struct.unpack("!B", value)[0])
                except (dpkt.UnpackError, struct.error):
                    self.transport_wscale = None

            elif option[0] == dpkt.tcp.TCP_OPT_SACKOK:
                # SACK permitted, RFC 2018
                self.transport_sack_enabled = True

            elif option[0] == dpkt.tcp.TCP_OPT_SACK:
                # SACK, RFC 2018
                (
                    self.transport_sack_1_from,
                    self.transport_sack_1_to,
                    self.transport_sack_2_from,
                    self.transport_sack_2_to,
                    self.transport_sack_3_from,
                    self.transport_sack_3_to,
                ) = self.decode_sack(value)

            elif option[0] == dpkt.tcp.TCP_OPT_TIMESTAMP:
                # timestamp, RFC 7323
                try:
                    ts = struct.unpack("!II", value)
                    self.transport_tsval = ts[0]
                    self.transport_tsecr = ts[1]
                except (dpkt.UnpackError, struct.error):
                    self.transport_tsval = None
                    self.transport_tsecr = None

        return transport.data

    def decode_udp_header(self, transport: dpkt.udp.UDP) -> Optional[Any]:
        """
        Decode the UDP header.

        Args:
            transport (dpkt.udp.UDP): The UDP packet.

        Returns:
            Optional[Any]: The UDP data.
        """
        # - Type
        self.transport_type = "UDP"

        # Transport length
        self.transport_header_len = getattr(transport, "__hdr_len__")
        self.transport_options_len = 0
        self.transport_data_len = getattr(transport, "ulen") - self.transport_header_len
        self.transport_capture_len = len(transport.data)

        # - Source
        self.transport_src_port = getattr(transport, "sport")

        # - Destination
        self.transport_dst_port = getattr(transport, "dport")

        return transport.data

    def decode_sctp_header(self, transport: dpkt.sctp.SCTP) -> Optional[Any]:
        """
        Decode the SCTP header.

        Args:
            transport (dpkt.sctp.SCTP): The SCTP packet.

        Returns:
            Optional[Any]: The SCTP data.
        """
        # - Type
        self.transport_type = "SCTP"

        # Transport length
        self.transport_header_len = getattr(transport, "__hdr_len__")
        self.transport_capture_len = len(transport.data)

        # - Source
        self.transport_src_port = getattr(transport, "sport")
        # - Destination
        self.transport_dst_port = getattr(transport, "dport")

        self.transport_options_len = 0
        for chunk in transport.chunks:
            if chunk.type == dpkt.sctp.DATA:
                self.transport_options_len += chunk.__hdr_len__
                transport = chunk
                break

            self.transport_options_len += chunk.len

        self.transport_data_len = (
            self.ip_len - self.transport_header_len - self.transport_options_len
        )

        if isinstance(transport, dpkt.sctp.Chunk):
            try:
                # - SEQ
                self.transport_seq = struct.unpack("!L", transport.data[0:4])[0]
                # - CID
                self.transport_cid = struct.unpack("!H", transport.data[4:6])[0]
                # - PKN
                self.transport_pkn = struct.unpack("!H", transport.data[6:8])[0]
            except struct.error:
                pass

        return transport.data

    def __init__(
        self,
        num: int,
        utc_date_time: datetime.datetime,
        eth: Optional[dpkt.ethernet.Ethernet],
        outerip: Optional[Union[dpkt.ip.IP, dpkt.ip6.IP6]],
        transport_port_cb: dict[str, Any],
        meta_values: Optional[dict[str, str]] = None,
    ) -> None:
        """
        Initialize an E2EPacket object.

        Args:
            eth: The Ethernet packet.
            outerip: The outer IP packet.

        Returns:
            None.
        """
        if meta_values is None:
            meta_values = {}

        self.create_empty_attr()

        # Packet Number
        self.num = num

        # UTC Date Time
        self.utc_date_time = utc_date_time

        # Meta Values: to be inserted in the parquet file
        self.meta_values = meta_values
        for key, value in meta_values.items():
            setattr(self, key, value)

        # Get outer IP
        if eth:
            outerip = self.decode_eth(eth)

        # Get Inner IP
        if outerip:
            innerip = self.decode_tunnels(outerip)
        else:
            innerip = None

        if innerip:
            transport = self.decode_ip_header(innerip)

            if isinstance(transport, dpkt.esp.ESP):
                transport = self.decode_esp(transport)

            app = None
            appdata = None

            # ICMP...
            if isinstance(transport, (dpkt.icmp.ICMP, dpkt.icmp6.ICMP6)):
                app = self.decode_icmp_header(transport)

            # TCP...
            if isinstance(transport, dpkt.tcp.TCP):
                app = self.decode_tcp_header(transport)

            # UDP...
            if isinstance(transport, dpkt.udp.UDP):
                app = self.decode_udp_header(transport)

            # SCTP...
            if isinstance(transport, dpkt.sctp.SCTP):
                app = self.decode_sctp_header(transport)

            # Session and Applications Decoding...
            self.app_type = None
            self.app_seq = None
            self.app_request = None
            self.app_response = None

            appdata = None

            # Transport Port Callback
            if self.transport_type == "ICMP":
                appdata = transport_port_cb["ICMP"].decode(self, transport, app)
            elif self.transport_type in ("UDP", "TCP", "SCTP"):
                p = min(self.transport_src_port, self.transport_dst_port)
                if p in transport_port_cb[self.transport_type] and p > 0:
                    appdata = transport_port_cb[self.transport_type][p].decode(
                        self, transport, app
                    )

                else:
                    p = max(self.transport_src_port, self.transport_dst_port)
                    if p in transport_port_cb[self.transport_type] and p > 0:
                        appdata = transport_port_cb[self.transport_type][p].decode(
                            self, transport, app
                        )

            # If no application data was found...
            if self.app_type is None and self.transport_type in ("UDP", "TCP", "SCTP"):
                # Use port 0 as list of undefined decoders to be tried
                for decoder in transport_port_cb[self.transport_type][0]:
                    appdata = decoder(self, transport, app)
                    if appdata is not None:
                        break

            # If no application data was found...
            if self.app_type is None:
                if app is not None:
                    self._not_decoded_data = list(bytes(app))
            else:
                if appdata is not None:
                    # if appdata is iterable
                    if self.app_type in transport_port_cb["iterable"]:
                        self._not_decoded_data = []
                        for avp in appdata:
                            self._not_decoded_data.extend(list(bytes(avp)))
                    else:
                        self._not_decoded_data = list(bytes(appdata))
