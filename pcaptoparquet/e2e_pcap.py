# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause

"""
This module provides the E2EPcap class for working with PCAP files.

The E2EPcap class represents a PCAP file and provides methods for exporting
the data in different formats.

Example usage:
    # Create an instance of E2EPcap
    pcap = E2EPcap(tags=["tag1", "tag2"], ctype="Client", pcap_full_name="example.pcap")

    # Export the data in raw format
    pcap.export(outformat="raw", output="output.txt")

    # Export the data in JSON format
    pcap.export(outformat="json", output="output.json")
"""
import datetime
import gc
import io
import json
import os
import struct
import sys
import warnings
from typing import Any, Dict, Optional, Tuple, Union

import dpkt
import polars as pl
from polars.exceptions import CategoricalRemappingWarning

from .e2e_config import E2EConfig
from .e2e_packet import E2EPacket
from .e2e_parallel import PCAPParallel

# DataFrames are comming from different processes
# and have different categories, so we need to remap them
warnings.simplefilter("ignore", category=CategoricalRemappingWarning)


def process_partial_pcap(
    file_handle: Any, params: Optional[dict[str, Any]] = None
) -> io.BytesIO:
    """
    Process a partial PCAP file.
    This is a wrapper around process_pcap_packet that reads the PCAP file in chunks.
    """
    return io.BytesIO(
        E2EPcap.process_pcap_common(
            pcap=dpkt.pcap.Reader(file_handle), params=params
        ).serialize()
    )


def process_partial_pcapng(
    file_handle: Any, params: Optional[dict[str, Any]] = None
) -> io.BytesIO:
    """
    Process a partial PCAP file.
    This is a wrapper around process_pcap_packet that reads the PCAP file in chunks.
    """
    return io.BytesIO(
        E2EPcap.process_pcap_common(
            pcap=dpkt.pcapng.Reader(file_handle), params=params
        ).serialize()
    )


# Utility class to encode complex objects to JSON
class ComplexEncoder(json.JSONEncoder):
    """
    A JSON encoder that can handle complex objects.
    """

    def default(self, o: Any) -> Any:
        if hasattr(o, "to_json"):
            return o.to_json()

        return json.JSONEncoder.default(self, o)


# The E2EPcap class
class E2EPcap:
    """
    The E2EPcap class represents a PCAP file and provides
    methods for exporting the data in different formats.
    """

    # User provided tags and values
    _common_user_meta = {
        "collection_type": "category",
    }

    # PCAP file metadata
    _common_pcap_meta = {"encapsulation": "category", "snaplen": "UInt32"}

    @staticmethod
    def get_separator() -> str:
        """
        Returns the separator used in the output files.
        """
        return E2EPacket.SEPARATOR

    @staticmethod
    def _get_outer_ip_and_eth(
        encapsulation: str, buf: bytes
    ) -> Tuple[
        Optional[dpkt.ethernet.Ethernet], Optional[Union[dpkt.ip.IP, dpkt.ip6.IP6]]
    ]:
        """
        Extract Ethernet and Outer IP packet based on encapsulation.
        """
        eth = None
        outerip = None

        try:
            if encapsulation == "Linux cooked capture":
                sll = dpkt.sll.SLL(buf)
                if isinstance(sll.data, dpkt.ethernet.Ethernet):
                    eth = sll.data
                if isinstance(sll.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
                    outerip = sll.data
            elif encapsulation == "Ethernet":
                eth = dpkt.ethernet.Ethernet(buf)
            elif encapsulation == "Loopback Raw":
                if dpkt.compat_ord(buf[4]) == 0x45:
                    # IP version 4 + header len 20 bytes
                    outerip = dpkt.ip.IP(buf[4:])
                elif dpkt.compat_ord(buf[4]) & 0xF0 == 0x60:
                    # IP version 6
                    outerip = dpkt.ip6.IP6(buf[4:])
            elif encapsulation == "Raw IP":
                if dpkt.compat_ord(buf[0]) == 0x45:
                    # IP version 4 + header len 20 bytes
                    outerip = dpkt.ip.IP(buf)
                elif dpkt.compat_ord(buf[0]) & 0xF0 == 0x60:
                    # IP version 6
                    outerip = dpkt.ip6.IP6(buf)
        except (dpkt.UnpackError, struct.error, IndexError):
            pass

        return eth, outerip

    @staticmethod
    def process_pcap_packet(
        num: int,
        timestamp: float,
        buf: bytes,
        encapsulation: str,
        transport_port_cb: dict[str, Any],
        meta_values: Optional[Dict[Any, Any]] = None,
    ) -> E2EPacket:
        """
        Process a single PCAP packet.
        """
        if meta_values is None:
            meta_values = {}

        utc_date_time = datetime.datetime.fromtimestamp(
            float(timestamp), datetime.timezone.utc
        )

        eth, outerip = E2EPcap._get_outer_ip_and_eth(encapsulation, buf)

        if outerip is None and eth is None:
            raise ValueError("Unknown encapsulation type: " + str(encapsulation))

        return E2EPacket(
            num,
            utc_date_time,
            eth,
            outerip,
            transport_port_cb,
            meta_values=meta_values,
        )

    @staticmethod
    def datalink_to_encapsulation(datalink: int) -> str:
        """
        Converts the datalink value to a string name.

        Args:
            datalink (int): The datalink value.

        Returns:
            str: The datalink name.
        """
        if datalink in [dpkt.pcap.DLT_LINUX_SLL]:
            encapsulation = "Linux cooked capture"
        elif datalink in [dpkt.pcap.DLT_EN10MB]:
            encapsulation = "Ethernet"
        elif datalink in [
            dpkt.pcap.DLT_NULL,
            dpkt.pcap.DLT_LOOP,
            dpkt.pcap.DLT_RAW,
        ]:
            encapsulation = "Loopback Raw"
        elif datalink in [101]:
            encapsulation = "Raw IP"
        else:
            raise ValueError("Unknown datalink type: " + str(datalink))

        return encapsulation

    @staticmethod
    def add_error_to_dict_list(
        pcap_dict_list: Dict[str, Any],
        pcap_dtypes: Dict[str, str],
        num: int,
        error_message: str,
    ) -> Dict[str, Any]:
        """
        Add error information to the dictionary list.
        This is used to add error information to the dictionary list
        when processing a PCAP file.
        """
        for key in pcap_dtypes:
            if key == "num":
                pcap_dict_list[key].append(num)
            elif key == "error":
                pcap_dict_list[key].append(True)
            elif key == "error_message":
                pcap_dict_list[key].append(error_message)
            else:
                pcap_dict_list[key].append(None)
        pcap_dict_list["not_decoded_data"].append(None)
        return pcap_dict_list

    @staticmethod
    def _initialize_pcap_dict_list(pcap_dtypes: dict[str, str]) -> dict[str, Any]:
        """
        Initialize the dictionary list for Polars DataFrame.
        """
        pcap_dict_list: dict[str, Any] = {key: [] for key in pcap_dtypes}
        pcap_dict_list["not_decoded_data"] = []
        return pcap_dict_list

    @staticmethod
    def _process_and_append_packet(
        num: int,
        timestamp: float,
        buf: bytes,
        encapsulation: str,
        transport_port_cb: dict[str, Any],
        meta_values: dict[str, str],
        pcap_dtypes: dict[str, str],
        pcap_dict_list: dict[str, Any],
    ) -> None:
        """
        Process a single packet and append it to the dictionary list.
        """
        try:
            e2e_pkt = E2EPcap.process_pcap_packet(
                num,
                timestamp,
                buf,
                encapsulation,
                transport_port_cb,
                meta_values=meta_values,
            )
            new_row = e2e_pkt.to_dict(pcap_dtypes)
            for key in pcap_dtypes:
                pcap_dict_list[key].append(new_row[key])
            pcap_dict_list["not_decoded_data"].append(e2e_pkt.get_not_decoded_data())
        except (ValueError, struct.error, dpkt.UnpackError):
            E2EPcap.add_error_to_dict_list(
                pcap_dict_list, pcap_dtypes, num, "Error processing packet"
            )

    @staticmethod
    def _print_packet(
        e2e_pkt: E2EPacket, outformat: str, file_handle: Any, sep_: str
    ) -> str:
        """
        Print the packet in the specified format.
        """
        if outformat == "txt":
            print(
                str(e2e_pkt),
                file=file_handle,
            )
        elif outformat == "json":
            print(
                sep_  # Ugly hack to avoid the first comma
                + json.dumps(e2e_pkt.to_json(), cls=ComplexEncoder),
                file=file_handle,
            )
            return ","
        return sep_

    @staticmethod
    def process_pcap_common(
        pcap: Any, params: Optional[dict[str, Any]] = None
    ) -> pl.DataFrame:
        """
        Process a partial PCAP file.
        This is a wrapper around process_pcap_packet that reads the PCAP file in chunks.
        """
        if params is None:
            pcap_dtypes = E2EPacket.get_dtypes()
            meta_values: dict[str, str] = {}
            encapsulation = E2EPcap.datalink_to_encapsulation(pcap.datalink())
            transport_port_cb = E2EConfig().get_transport_port_cb()
            outformat = "parquet"
            file_handle = None
            use_polars = True
            pktnum = 0
        else:
            pcap_dtypes = params["pcap_dtypes"]
            encapsulation = params["encapsulation"]

            if params["transport_port_cb"] is None:
                # If transport_port_cb is None, use the default from E2EConfig
                # This is needed for parallel processing
                transport_port_cb = E2EConfig(
                    configpath=params["configpath"]
                ).get_transport_port_cb()
            else:
                # Otherwise, use the provided transport_port_cb
                transport_port_cb = params["transport_port_cb"]

            meta_values = params["meta_values"]
            outformat = params["outformat"]
            file_handle = params["file_handle"]
            use_polars = params["use_polars"]
            pktnum = params["pktnum"]

        if not use_polars and not file_handle:
            raise ValueError("File handle is required for non-polars output formats.")

        pcap_dict_list = E2EPcap._initialize_pcap_dict_list(pcap_dtypes)

        num = 0
        sep_ = ""
        for timestamp, buf in pcap:

            num = num + 1

            if buf is None or len(buf) == 0:
                # Add empty values to the dictionary
                E2EPcap.add_error_to_dict_list(
                    pcap_dict_list, pcap_dtypes, num, "Empty buffer"
                )
                continue

            if pktnum in (0, num):
                if use_polars:
                    E2EPcap._process_and_append_packet(
                        num,
                        timestamp,
                        buf,
                        encapsulation,
                        transport_port_cb,
                        meta_values,
                        pcap_dtypes,
                        pcap_dict_list,
                    )

                else:
                    try:
                        e2e_pkt = E2EPcap.process_pcap_packet(
                            num,
                            timestamp,
                            buf,
                            encapsulation,
                            transport_port_cb,
                            meta_values=meta_values,
                        )
                        sep_ = E2EPcap._print_packet(
                            e2e_pkt, outformat, file_handle, sep_
                        )
                    except (ValueError, struct.error, dpkt.UnpackError):
                        pass

        if use_polars:
            # Convert dtypes based on pcap_dtypes
            pl_schema = E2EPcap.get_polars_schema(pcap_dtypes)

            pl_pcaparquet = pl.DataFrame(pcap_dict_list, schema=pl.Schema(pl_schema))

        else:
            pl_pcaparquet = pl.DataFrame()

            # Print the JSON header
            if outformat == "json":
                print("]}", file=file_handle)

        return pl_pcaparquet

    def add_tags_to_user_meta(self, tags: dict[str, str]) -> None:
        """
        Adds the user tags to the user metadata as categorical data.
        """
        for key in tags:
            new_key = E2EPacket.validate_str(key)
            self._common_user_meta[new_key] = "category"
            setattr(self, new_key, tags[key])

    def get_meta_values(
        self, meta_list: Optional[Tuple[Dict[str, str], Dict[str, str]]] = None
    ) -> Dict[str, str]:
        """
        Returns the metadata values as a list.

        Args:
            meta_list (tuple, optional): The list of metadata dictionaries.
            Defaults to an empty tuple.

        Returns:
            list: The metadata values as a list.
        """
        if meta_list is None:
            return {}
        meta_values = {}
        for meta in meta_list:
            for key in meta:
                meta_values[key] = getattr(self, key)
        return meta_values

    def to_json(self) -> dict[str, Any]:
        """
        Converts the E2EPcap object to a JSON-compatible dictionary.

        Args:
            d_ (dict, optional): The dictionary to populate with the object's
            attributes. Defaults to an empty dictionary.

        Returns:
            dict: The JSON-compatible dictionary.
        """
        d_ = {}
        for field_name in list(self._common_user_meta.keys()):
            d_[field_name] = getattr(self, field_name)
        for field_name in list(self._common_pcap_meta.keys()):
            d_[field_name] = getattr(self, field_name)
        d_["packets"] = []
        return d_

    def __init__(
        self,
        tags: Optional[dict[str, str]] = None,
        ctype: Optional[str] = None,
        pcap_full_name: Optional[str] = None,
        config: Optional[E2EConfig] = None,
        pcapng: bool = False,
        parallel: bool = False,
    ):
        """
        Initializes a new instance of the E2EPcap class.

        Args:
            tags (list): The user tags.
            ctype (str): The collection type.
            pcap_full_name (str): The full name of the PCAP file.
            config (E2EConfig): The E2EConfig object with protocol configuration
                and post-processing callbacks.
            pcapng (bool, optional): Whether the PCAP file is in PCAPNG format.
                Defaults to False.
            parallel (bool, optional): Whether to use parallel processing.
                Defaults to False.
            callbackpath (str, optional): The callback path. Defaults to None.
        """
        # * User Tags
        if tags is not None:
            self.add_tags_to_user_meta(tags)

        # * Collection Type (Unknown, Client, Network, Server)
        if ctype is not None and ctype in ["Client", "Network", "Server"]:
            self.collection_type = ctype
        else:
            self.collection_type = "Unknown"

        # Open PCAP
        self.pcap_name = str(pcap_full_name)
        if pcap_full_name is not None:
            pcapng = (
                pcapng
                or PCAPParallel.check_pcapng(self.pcap_name)
                or ".pcapng." in self.pcap_name
            )
            # This handles compressed files...
            self.file = PCAPParallel.open_maybe_compressed(self.pcap_name)
        else:
            self.file = sys.stdin.buffer  # .raw

        if pcapng:
            self.pcap = dpkt.pcapng.Reader(self.file)
        else:
            self.pcap = dpkt.pcap.Reader(self.file)

        # Encapsulation
        self.datalink = self.pcap.datalink()
        self.encapsulation = self.datalink_to_encapsulation(self.datalink)

        # Snaplen
        self.snaplen = int(self.pcap.snaplen)

        # Parallel processing of the PCAP file
        # Only parallelize if the file is larger than a certain size.
        self.ps = None
        if pcap_full_name is not None:
            self.file_size = os.path.getsize(self.pcap_name)
            if not isinstance(self.file, io.BufferedReader):
                # Likely a compressed file assumme 4x the size
                self.file_size = self.file_size * 4
        else:
            # Standard input does not have a size
            self.file_size = 0

        if config is None:
            config = E2EConfig()

        if parallel and pcap_full_name and self.file_size > 500_000:  # 500KB
            # Only parallelize if the file is larger than
            # a certain size and the format is parquet.
            if pcapng:
                self.ps = PCAPParallel(
                    pcap_full_name,
                    callback=process_partial_pcapng,
                )
            else:
                self.ps = PCAPParallel(
                    pcap_full_name,
                    callback=process_partial_pcap,
                )

            # Save config path for multi-processing
            self.configpath = config.configpath

            # Protocol configurations
            self.transport_port_cb = None

        else:

            # Save config path for multi-processing
            self.configpath = None

            # Protocol configurations
            self.transport_port_cb = config.get_transport_port_cb()

        # Post-processing Callbacks
        self.post_callbacks = config.get_post_callbacks()

    def __del__(self) -> None:
        """
        Closes the PCAP file when the object is destroyed.
        """
        if not hasattr(self, "ps") or self.ps is None:
            self.file.close()

    @staticmethod
    def get_output_buffer(
        outformat: str = "parquet",
        output: Optional[str] = None,
        use_polars: bool = False,
    ) -> Any:
        """
        Returns the output buffer for the specified format.
        """
        f: Any = None

        if (outformat == "txt") or ((outformat == "json") and not use_polars):
            # Text output...
            if output:
                f = open(output, "w", encoding="utf-8")
            else:
                f = sys.stdout
        else:
            # Binary output...
            if output:
                f = open(output, "wb")
            else:
                f = sys.stdout.buffer
        return f

    @staticmethod
    def write_dataframe(
        df: pl.DataFrame, file_handle: Any, outformat: str, close_fh: bool
    ) -> None:
        """
        Writes the Polars DataFrame to the output file.
        """
        # Write to file
        if outformat == "parquet":
            df.write_parquet(file_handle)
        elif outformat == "txt":
            df.write_csv(
                file_handle, include_header=True, separator=E2EPacket.SEPARATOR
            )
        elif outformat == "json":
            df.write_ndjson(file_handle)

        file_handle.flush()

        if close_fh:
            file_handle.close()

    @staticmethod
    def get_polars_schema(pcap_dtypes: dict[str, str]) -> dict[str, Any]:
        """
        Returns the Polars schema for the specified PCAP data types.
        """
        pl_schema: dict[str, Any] = {}
        for key in pcap_dtypes:
            if pcap_dtypes[key] in ["UInt8"]:
                pl_schema[key] = pl.UInt8()
            elif pcap_dtypes[key] in ["UInt16"]:
                pl_schema[key] = pl.UInt16()
            elif pcap_dtypes[key] in ["UInt32"]:
                pl_schema[key] = pl.UInt32()
            elif pcap_dtypes[key] in ["UInt64"]:
                pl_schema[key] = pl.UInt64()
            elif pcap_dtypes[key] in ["Float32"]:
                pl_schema[key] = pl.Float32()
            elif pcap_dtypes[key] in ["Float64"]:
                pl_schema[key] = pl.Float64()
            elif pcap_dtypes[key] in ["boolean"]:
                pl_schema[key] = pl.Boolean()
            elif pcap_dtypes[key] in ["string"]:
                pl_schema[key] = pl.String()
            elif pcap_dtypes[key] in ["datetime64[ns, UTC]"]:
                pl_schema[key] = pl.Datetime(time_unit="ns", time_zone="UTC")
            elif pcap_dtypes[key] in ["category"]:
                pl_schema[key] = pl.Categorical()
            else:
                pl_schema[key] = pl.Object()

        pl_schema["not_decoded_data"] = pl.List(pl.UInt8())

        return pl_schema

    def export(
        self,
        outformat: str = "parquet",
        output: Optional[str] = None,
        pktnum: int = 0,
        return_df: bool = False,
    ) -> pl.DataFrame:
        """
        Exports the PCAP data in the specified format.

        Args:
            outformat (str, optional): The export format. Defaults to "txt".
            output (str, optional): The output file path. Defaults to None
                (prints to stdout).
            pktnum (int, optional): The packet number to export. Defaults to 0
                (exports all packets).

        Raises:
            ValueError: If an invalid format is specified.

        Example usage:
            # Export the data in txt format
            pcap.export(outformat="txt", output="output.txt")

            # Export the data in JSON format
            pcap.export(outformat="json", output="output.json")
        """
        use_polars = (
            self.ps is not None
            or len(self.post_callbacks) > 0
            or outformat == "parquet"
            or return_df
        )

        close_fh = False
        file_handle = None

        if not return_df:
            file_handle = E2EPcap.get_output_buffer(outformat, output, use_polars)
            close_fh = output is not None

        pcap_dtypes = E2EPacket.get_dtypes(
            (self._common_user_meta, self._common_pcap_meta)
        )

        if use_polars:
            # Create empty dictionary for the polars dataframe columns
            pcap_dict_list: dict[str, Any] = {}

            for key in pcap_dtypes:
                pcap_dict_list[key] = []

            pcap_dict_list["not_decoded_data"] = []

        elif outformat == "txt":
            # Print the CSV header
            print(
                E2EPacket.header((self._common_user_meta, self._common_pcap_meta)),
                file=file_handle,
            )
        elif outformat == "json":
            # Print the JSON header
            print(json.dumps(self.to_json(), cls=ComplexEncoder)[:-2], file=file_handle)

        meta_values = self.get_meta_values(
            (self._common_user_meta, self._common_pcap_meta)
        )

        # Multiprocessing
        if self.ps is not None:
            # Parallel processing
            partial_results = self.ps.split(
                params={
                    "encapsulation": self.encapsulation,
                    "configpath": self.configpath,
                    "transport_port_cb": None,
                    "meta_values": meta_values,
                    "pcap_dtypes": pcap_dtypes,
                    "outformat": outformat,
                    "file_handle": None,  # No file handle in parallel processing
                    "pktnum": pktnum,
                    "use_polars": use_polars,
                }
            )

            self.ps.shutdown()  # Shutdown the parallel processing

            pl_list: list[pl.DataFrame] = []

            # merge the results
            while len(partial_results) > 0:
                partial = partial_results.pop(0)
                # If the result is ready, add it to the list
                pl_list.append(pl.DataFrame.deserialize(partial.result()))

            del partial_results
            gc.collect()

            # Sort results by utc_date_time of the first packet
            pl_list.sort(
                key=lambda x: x.filter(pl.col("utc_date_time").is_not_null())[
                    "utc_date_time"
                ][0]
            )

            pl_pcaparquet = pl.concat(pl_list)

            pl_list.clear()  # Clear the list to free memory
            del pl_list  # Clear the list to free memory
            gc.collect()

            total_len = len(pl_pcaparquet)

            # Create or update num column with sequential numbers
            # from 1 to total_len
            pl_pcaparquet = pl_pcaparquet.with_columns(
                pl.arange(1, total_len + 1).cast(pl.UInt32).alias("num")
            )

        else:
            # Single processing
            pl_pcaparquet = E2EPcap.process_pcap_common(
                pcap=self.pcap,
                params={
                    "encapsulation": self.encapsulation,
                    "configpath": None,
                    "transport_port_cb": self.transport_port_cb,
                    "meta_values": meta_values,
                    "pcap_dtypes": pcap_dtypes,
                    "outformat": outformat,
                    "file_handle": file_handle,
                    "pktnum": pktnum,
                    "use_polars": use_polars,
                },
            )

        if use_polars:
            # Call callback for further processing
            for callback in self.post_callbacks:
                pl_pcaparquet = callback(pl_pcaparquet)

            # Drop not_decoded_data column if exists
            if "not_decoded_data" in pl_pcaparquet.columns:
                pl_pcaparquet = pl_pcaparquet.drop("not_decoded_data")

            if return_df:
                return pl_pcaparquet

            E2EPcap.write_dataframe(pl_pcaparquet, file_handle, outformat, close_fh)

        if close_fh:
            file_handle.close()  # type: ignore
        else:
            sys.stdout.flush()

        return pl.DataFrame()
