# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause
"""
This module add pcapng support to the PCAPParallel class.
"""

import bz2
import gc
import gzip
import io
import lzma
import multiprocessing
import os
from concurrent.futures import Future, ProcessPoolExecutor
from math import ceil
from struct import unpack as struct_unpack
from typing import Any, List, Optional

import dpkt
import psutil


class PcapngReader:
    """Simple pypcap-compatible pcapng file reader."""

    def setfilter(self, value: Any, optimize: int = 1) -> None:
        """
        Set a filter for the pcapng reader.
        This method is not implemented for pcapng readers.
        """
        raise NotImplementedError

    def __init__(self, fileobj: Any) -> None:
        """
        Initialize a pcapng file reader.
        """
        self.name = getattr(fileobj, "name", f"<{fileobj.__class__.__name__}>")
        self.__f = fileobj

        shb = dpkt.pcapng.SectionHeaderBlock()
        buf = self.__f.read(getattr(shb, "__hdr_len__"))
        if len(buf) < getattr(shb, "__hdr_len__"):
            raise ValueError("invalid pcapng header")

        # unpack just the header since endianness is not known
        shb.unpack_hdr(buf)
        if getattr(shb, "type") != dpkt.pcapng.PCAPNG_BT_SHB:
            raise ValueError("invalid pcapng header: not a SHB")

        # determine the correct byte order and reload full SHB
        if getattr(shb, "bom") == dpkt.pcapng.BYTE_ORDER_MAGIC_LE:
            self.__le = True
            buf += self.__f.read(
                dpkt.pcapng._swap32b(shb.len) - getattr(shb, "__hdr_len__")
            )
            shb = dpkt.pcapng.SectionHeaderBlockLE(buf)
        elif getattr(shb, "bom") == dpkt.pcapng.BYTE_ORDER_MAGIC:
            self.__le = False
            buf += self.__f.read(shb.len - getattr(shb, "__hdr_len__"))
            shb = dpkt.pcapng.SectionHeaderBlock(buf)
        else:
            raise ValueError("unknown endianness")

        # Need to save the SHB for later use
        self.shb = shb

        # check if this version is supported

        if getattr(shb, "v_major") != dpkt.pcapng.PCAPNG_VERSION_MAJOR:
            raise ValueError(
                "Unknown pcapng version "
                + f'{getattr(shb, "v_major")}.{getattr(shb, "v_minor")}'
            )

        # look for a mandatory IDB
        idb = None
        while 1:
            buf = self.__f.read(8)
            if len(buf) < 8:
                break

            blk_type, blk_len = struct_unpack("<II" if self.__le else ">II", buf)
            buf += self.__f.read(blk_len - 8)

            if blk_type == dpkt.pcapng.PCAPNG_BT_IDB:
                idb = (
                    dpkt.pcapng.InterfaceDescriptionBlockLE(buf)
                    if self.__le
                    else dpkt.pcapng.InterfaceDescriptionBlock(buf)
                )
                break
            # just skip other blocks

        if idb is None:
            raise ValueError("IDB not found")

        # set timestamp resolution and offset
        self._divisor = 1000000  # defaults
        self._tsoffset = 0
        for opt in idb.opts:
            if opt.code == dpkt.pcapng.PCAPNG_OPT_IF_TSRESOL:
                # if MSB=0, the remaining bits is a neg power
                #     of 10 (e.g. 6 means microsecs)
                # if MSB=1, the remaining bits is a neg power
                #     of 2 (e.g. 10 means 1/1024 of second)
                opt_val = struct_unpack("b", opt.data)[0]
                pow_num = 2 if opt_val & 0b10000000 else 10
                self._divisor = pow_num ** (opt_val & 0b01111111)

            elif opt.code == dpkt.pcapng.PCAPNG_OPT_IF_TSOFFSET:
                # 64-bit int that specifies an offset (in seconds) that
                # must be added to the timestamp of each packet
                self._tsoffset = struct_unpack("<q" if self.__le else ">q", opt.data)[0]

        if getattr(idb, "linktype") in dpkt.pcapng.dltoff:
            self.dloff = dpkt.pcapng.dltoff[getattr(idb, "linktype")]
        else:
            self.dloff = 0

        self.idb = idb
        self.snaplen = getattr(idb, "snaplen")
        self.filter = ""


#        self.__iter = dpkt.pcapng.Reader.iter(self)


class PCAPParallel:
    """
    Based on PCAPParallel class to provide a more specific implementation
    """

    def __init__(self, pcap_file: str, callback: Any) -> None:
        """
        Quickly reads a PCAP file and splits the contents.
        Each file is split into multiple io.BytesIO streams, which will
        result in loading the entire contents into memory.  Callbacks for
        each section will be executed in a separate process.
        """
        self.pcap_file: str = pcap_file
        self.callback = callback

        self.params: Optional[dict[str, Any]] = None

        self.maximum_count = 0
        self.header: bytes = bytes()
        self.buffer: bytes = bytes()
        self.unprocessed_bytes: List[int] = []
        self.processed_bytes: int = 0
        self.split_packets: int = 0
        self.split_sizes: List[int] = []
        self.dpkt_data = None
        self.our_data = None
        self.results: List[Any] = []
        self.process_pool = ProcessPoolExecutor()
        self.spawned_processes: int = 0

        if not os.path.exists(self.pcap_file):
            raise ValueError(f"failed to find pcap file '{self.pcap_file}'")

    def shutdown(self) -> None:
        """
        Shutdown the process pool executor
        """
        if self.process_pool is not None:
            self.process_pool.shutdown(wait=True, cancel_futures=False)

        if self.dpkt_data is not None:
            self.dpkt_data.close()

        if self.our_data is not None:
            self.our_data.close()

    @staticmethod
    def open_maybe_compressed(filename: str) -> Any:
        """Opens a pcap file, potentially decompressing it."""

        magic_dict = {
            bytes([0x1F, 0x8B, 0x08]): "gz",
            bytes([0x42, 0x5A, 0x68]): "bz2",
            bytes([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]): "xz",
        }

        max_len = max(len(x) for x in magic_dict)

        # read the first 24 bytes which is the pcap header
        with open(filename, "rb") as base_handle:
            file_start = base_handle.read(max_len)

        return_handle: Optional[Any] = None

        for magic, filetype in magic_dict.items():
            if file_start.startswith(magic):
                # Compressed file, try to open it with the appropriate module
                # and return the handle
                try:
                    if filetype == "gz":
                        return_handle = gzip.open(filename, "rb")
                    elif filetype == "bz2":
                        return_handle = bz2.open(filename, "rb")
                        setattr(return_handle, "name", filename)
                    elif filetype == "xz":
                        return_handle = lzma.open(filename, "rb")
                    else:
                        raise ValueError("unknown compression error")
                except Exception as e:
                    # likely we failed to find a compression module
                    raise ValueError("cannot decode file") from e

                return return_handle

        # return a raw file and hope it's not compressed'
        return open(filename, "rb")

    @staticmethod
    def check_pcapng(pcap_file: str) -> bool:
        """
        Determine if the file is a pcapng file
        """
        # read the first 24 bytes which is the pcap header
        # pcap	Wireshark/tcpdump/… - pcap	d4 c3 b2 a1	ÔÃ²¡	pcap;cap;dmp
        # pcapng	Wireshark/… - pcapng	0a 0d 0d 0a	\n\r\r\n	pcapng;ntar
        magic_ng = bytes([0x0A, 0x0D, 0x0D, 0x0A])
        max_len = len(magic_ng)

        base_handle = PCAPParallel.open_maybe_compressed(pcap_file)
        file_start = base_handle.read(max_len)
        base_handle.close()

        if isinstance(file_start, bytes):
            return file_start.startswith(magic_ng)

        return ".pcapng" in pcap_file

    def is_pcapng(self) -> bool:
        """
        Determine if the file is a pcapng file
        """
        return PCAPParallel.check_pcapng(self.pcap_file)

    def dpkt_count_bytes_cb(
        self,
        timestamp: float,  # pylint: disable=unused-argument
        packet: bytes,  # pylint: disable=unused-argument
    ) -> None:
        """
        Handles each packet received by dpkt
        """
        self.unprocessed_bytes.append(self.dpkt_data.tell())  # type: ignore

    def set_split_sizes(self) -> None:
        """
        Attempt to calculate a reasonable split size
        """
        cores = multiprocessing.cpu_count()

        # Get available memory using psutil
        available_memory = psutil.virtual_memory().available

        self.dpkt_data = self.open_maybe_compressed(self.pcap_file)

        # now process with dpkt to pull out each packet
        if self.is_pcapng():
            pcap = dpkt.pcapng.Reader(self.dpkt_data)  # PcapngReader(size_handle)
        else:
            pcap = dpkt.pcap.Reader(self.dpkt_data)

        pcap.dispatch(self.maximum_count, self.dpkt_count_bytes_cb)

        # euristic to determine how many packets we can process in parallel
        # testing shows that we use more than 25 times the size of the pcap file
        # We rounded this to 32 times unprocessed_bytes[-1] divided by memory available
        # the we keep the following integer using ceil:
        mem_factor = int(ceil(32 * self.unprocessed_bytes[-1] / available_memory))

        self.split_packets = int(len(self.unprocessed_bytes) / cores / mem_factor) + 1

        pkt = self.split_packets
        pos_bytes = self.our_data.tell()  # type: ignore
        while pkt < len(self.unprocessed_bytes):
            self.split_sizes.append(self.unprocessed_bytes[pkt] - pos_bytes)
            pos_bytes = self.unprocessed_bytes[pkt]
            pkt += self.split_packets

        self.split_sizes.append(self.unprocessed_bytes[-1] - pos_bytes)

        self.dpkt_data.close()  # type: ignore

        self.unprocessed_bytes.clear()
        gc.collect()

    def spawn_process(self, bytes_to_read: int) -> None:
        """
        Saves the contents seen to this point into a new io.BytesIO
        """
        self.buffer = bytes(self.header)

        # read from our files current position to where the dpkt reader is
        self.buffer += self.our_data.read(bytes_to_read)  # type: ignore

        self.spawned_processes += 1

        self.results.append(
            self.process_pool.submit(
                self.callback, io.BytesIO(self.buffer), self.params
            )
        )

    def split(self, params: Optional[dict[str, Any]] = None) -> List[Future[Any]]:
        """
        Does the actual reading and splitting
        """
        self.params = params

        # open one for the dpkt reader and one for us independently
        self.our_data = self.open_maybe_compressed(self.pcap_file)

        # now process with dpkt to pull out each packet
        if self.is_pcapng():
            hdr_data = self.open_maybe_compressed(self.pcap_file)
            pcap_hdr = PcapngReader(hdr_data)  # Dummy Header Decoding
            hdr_data.close()

            hdr_bytes = self.our_data.read(  # type: ignore
                pcap_hdr.shb.len + pcap_hdr.idb.len
            )
        else:
            hdr_bytes = self.our_data.read(  # type: ignore
                getattr(dpkt.pcap.FileHdr, "__hdr_len__")
            )

        setattr(self, "header", hdr_bytes)

        # This must be called after reading the header
        self.set_split_sizes()

        for split_size in self.split_sizes:
            self.spawn_process(split_size)

        self.process_pool.shutdown(wait=True, cancel_futures=False)

        self.our_data.close()  # type: ignore

        return self.results
