# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause
"""
This module add pcapng support to the PCAPParallel class.
"""

import io
from concurrent.futures import Future
from typing import Any, List

import dpkt
import pcap_parallel
from dpkt.pcapng import SectionHeaderBlock, SectionHeaderBlockLE


class PcapngReader(dpkt.pcapng.Reader):  # type: ignore
    """Simple pypcap-compatible pcapng file reader."""

    def setfilter(self, value: Any, optimize: int = 1) -> None:
        raise NotImplementedError

    def __init__(self, fileobj: Any) -> None:
        """
        Initialize a pcapng file reader.
        """
        super().__init__(fileobj)

        self.name = getattr(fileobj, "name", f"<{fileobj.__class__.__name__}>")
        self.__f = fileobj

        shb = SectionHeaderBlock()
        shb_hdr_len = getattr(shb, "__hdr_len__")
        buf = self.__f.read(shb_hdr_len)
        shb.unpack_hdr(buf)

        # determine the correct byte order and reload full SHB
        shb_bom = getattr(shb, "bom")
        if shb_bom == dpkt.pcapng.BYTE_ORDER_MAGIC_LE:
            buf += self.__f.read(dpkt.pcapng._swap32b(shb.len) - shb_hdr_len)
            shb = SectionHeaderBlockLE(buf)
        elif shb_bom == dpkt.pcapng.BYTE_ORDER_MAGIC:
            buf += self.__f.read(shb.len - shb_hdr_len)
            shb = SectionHeaderBlock(buf)

        # Need to save the SHB for later use
        self.shb = shb


class PCAPParallel(pcap_parallel.PCAPParallel):  # type: ignore
    """
    Extends the PCAPParallel class to provide a more specific implementation
    """

    def is_pcapng(self) -> bool:
        """
        Determine if the file is a pcapng file
        """
        # read the first 24 bytes which is the pcap header
        # pcap	Wireshark/tcpdump/… - pcap	d4 c3 b2 a1	ÔÃ²¡	pcap;cap;dmp
        # pcapng	Wireshark/… - pcapng	0a 0d 0d 0a	\n\r\r\n	pcapng;ntar
        magic_ng = bytes([0x0A, 0x0D, 0x0D, 0x0A])
        max_len = len(magic_ng)

        base_handle = self.open_maybe_compressed(self.pcap_file)
        file_start = base_handle.read(max_len)
        base_handle.close()

        if isinstance(file_start, bytes):
            return file_start.startswith(magic_ng)

        return ".pcapng" in self.pcap_file

    def split(self) -> List[io.BytesIO] | List[Future]:  # type: ignore
        "Does the actual reading and splitting"

        # open one for the dpkt reader and one for us independently
        self.our_data = self.open_maybe_compressed(self.pcap_file)
        self.dpkt_data = self.open_maybe_compressed(self.pcap_file)

        self.set_split_size()

        # now process with dpkt to pull out each packet
        if self.is_pcapng():
            pcap = PcapngReader(self.dpkt_data)
            hdr_bytes = self.our_data.read(pcap.shb.len + pcap.idb.len)
        else:
            pcap = dpkt.pcap.Reader(self.dpkt_data)
            hdr_bytes = self.our_data.read(getattr(dpkt.pcap.FileHdr, "__hdr_len__"))

        setattr(self, "header", hdr_bytes)

        if self.pcap_filter:
            pcap.setfilter(self.pcap_filter)

        pcap.dispatch(self.maximum_count, self.dpkt_callback)

        # TODO: need to process the remaining bytes
        self.save_packets()

        self.process_pool.shutdown(wait=True, cancel_futures=False)

        return self.results  # type: ignore
