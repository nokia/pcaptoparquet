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
import json
import os
import sys
from typing import Any, Dict, Optional, Tuple

import dpkt
import polars as pl

from .e2e_config import E2EConfig
from .e2e_packet import E2EPacket
from .e2e_parallel import PCAPParallel


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

        sll = None
        eth = None
        outerip = None

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
    def process_partial_pcap(file_handle: Any) -> Dict[str, Any]:
        """
        Process a partial PCAP file.
        This is a wrapper around process_pcap_packet that reads the PCAP file in chunks.
        """

        pcap_dtypes = E2EPacket.get_dtypes()

        pcap_dict_list: dict[str, Any] = {}

        for key in pcap_dtypes:
            pcap_dict_list[key] = []

        pcap_dict_list["not_decoded_data"] = []

        meta_values: dict[str, str] = {}

        # read the pcap in and count all the sources
        pcap = dpkt.pcap.Reader(file_handle)

        encapsulation = E2EPcap.datalink_to_encapsulation(pcap.datalink())

        num = 0
        for timestamp, buf in pcap:
            num = num + 1

            if buf is None or len(buf) == 0:
                continue

            try:
                e2e_pkt = E2EPcap.process_pcap_packet(
                    num,
                    timestamp,
                    buf,
                    encapsulation,
                    E2EConfig().get_transport_port_cb(),
                    meta_values=meta_values,
                )
            except ValueError:
                continue

            new_row = e2e_pkt.to_dict(pcap_dtypes)  # Convert to dict

            for key in pcap_dtypes:
                pcap_dict_list[key].append(new_row[key])

            pcap_dict_list["not_decoded_data"].append(e2e_pkt.get_not_decoded_data())

        return pcap_dict_list

    @staticmethod
    def process_partial_pcapng(file_handle: Any) -> Dict[str, Any]:
        """
        Process a partial PCAP file.
        This is a wrapper around process_pcap_packet that reads the PCAP file in chunks.
        """

        pcap_dtypes = E2EPacket.get_dtypes()

        pcap_dict_list: dict[str, Any] = {}

        for key in pcap_dtypes:
            pcap_dict_list[key] = []

        pcap_dict_list["not_decoded_data"] = []

        meta_values: dict[str, str] = {}

        # read the pcap in and count all the sources
        pcap = dpkt.pcapng.Reader(file_handle)

        encapsulation = E2EPcap.datalink_to_encapsulation(pcap.datalink())

        num = 0
        for timestamp, buf in pcap:
            num = num + 1

            if buf is None or len(buf) == 0:
                continue

            try:
                e2e_pkt = E2EPcap.process_pcap_packet(
                    num,
                    timestamp,
                    buf,
                    encapsulation,
                    E2EConfig().get_transport_port_cb(),
                    meta_values=meta_values,
                )
            except ValueError:
                continue

            new_row = e2e_pkt.to_dict(pcap_dtypes)  # Convert to dict

            for key in pcap_dtypes:
                pcap_dict_list[key].append(new_row[key])

            pcap_dict_list["not_decoded_data"].append(e2e_pkt.get_not_decoded_data())

        return pcap_dict_list

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
                or self.pcap_name.endswith(".pcapng")
                or ".pcapng." in self.pcap_name
            )
            # This handles compressed files...
            self.file = PCAPParallel.open_maybe_compressed(self.pcap_name)
        else:
            self.file = sys.stdin.buffer  # .raw

        # Parallel processing of the PCAP file
        # Only parallelize if the file is larger than a certain size.
        self.ps = None
        if (
            parallel
            and pcap_full_name
            and os.path.getsize(pcap_full_name) > 500_000  # 500KB
        ):
            # Only parallelize if the file is larger than
            # a certain size and the format is parquet.
            if pcapng:
                self.ps = PCAPParallel(
                    pcap_full_name,
                    callback=E2EPcap.process_partial_pcapng,
                )
            else:
                self.ps = PCAPParallel(
                    pcap_full_name,
                    callback=E2EPcap.process_partial_pcap,
                )

        if pcapng:
            self.pcap = dpkt.pcapng.Reader(self.file)
        else:
            self.pcap = dpkt.pcap.Reader(self.file)

        # Encapsulation
        self.datalink = self.pcap.datalink()
        self.encapsulation = self.datalink_to_encapsulation(self.datalink)

        # Snaplen
        self.snaplen = int(self.pcap.snaplen)

        if config is None:
            config = E2EConfig()

        # Protocol configurations
        self.transport_port_cb = config.get_transport_port_cb()

        # Post-processing Callbacks
        self.post_callbacks = config.get_post_callbacks()

    def __del__(self) -> None:
        """
        Closes the PCAP file when the object is destroyed.
        """
        if self.ps is None:
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

        if use_polars:
            # Create empty dictionary for the polars dataframe columns
            pcap_dtypes = E2EPacket.get_dtypes(
                (self._common_user_meta, self._common_pcap_meta)
            )

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
            partial_results = self.ps.split()

            # Sort results by utc_date_time of the first packet
            partial_results.sort(
                key=lambda x: getattr(x, "result")()["utc_date_time"][0]
            )

            # merge the results
            ps_pcap_dict_list = partial_results.pop(0).result()  # type: ignore
            first_date = ps_pcap_dict_list["utc_date_time"][0]
            for partial in partial_results:
                next_pcap_dict_list = partial.result()  # type: ignore
                if next_pcap_dict_list["utc_date_time"][0] < first_date:
                    raise ValueError("Results are not sorted by utc_date_time")

                first_date = next_pcap_dict_list["utc_date_time"][0]
                for key in next_pcap_dict_list:
                    ps_pcap_dict_list[key].extend(next_pcap_dict_list[key])

            total_len = len(ps_pcap_dict_list["num"])
            ps_pcap_dict_list["num"] = list(range(1, total_len + 1))

            # Need to add the metadata values to the dictionary
            # from pcap_dtypes and meta_values
            for key in pcap_dtypes:
                # if key in ps_pcap_dict_list add it to pcap_dict_list:
                if key in ps_pcap_dict_list:
                    pcap_dict_list[key] = ps_pcap_dict_list[key]
                else:
                    pcap_dict_list[key] = [meta_values[key]] * total_len

            pcap_dict_list["not_decoded_data"] = ps_pcap_dict_list["not_decoded_data"]

        else:  # Single processing
            num = 0
            sep_ = ""
            for timestamp, buf in self.pcap:
                num = num + 1

                if buf is None or len(buf) == 0:
                    continue

                if pktnum == 0 or pktnum == num:
                    try:
                        e2e_pkt = self.process_pcap_packet(
                            num,
                            timestamp,
                            buf,
                            self.encapsulation,
                            self.transport_port_cb,
                            meta_values=meta_values,
                        )
                    except ValueError:
                        continue

                    # Print the packet for non parquet formats
                    if use_polars:  # Parquet or Polars
                        new_row = e2e_pkt.to_dict(pcap_dtypes)  # Convert to dict

                        for key in pcap_dtypes:
                            pcap_dict_list[key].append(new_row[key])

                        pcap_dict_list["not_decoded_data"].append(
                            e2e_pkt.get_not_decoded_data()
                        )

                    else:
                        if outformat == "txt":
                            print(
                                str(e2e_pkt),
                                file=file_handle,
                            )
                        elif outformat == "json":
                            try:
                                print(
                                    sep_  # Ugly hack to avoid the first comma
                                    + json.dumps(e2e_pkt.to_json(), cls=ComplexEncoder),
                                    file=file_handle,
                                )
                                sep_ = ","
                            except Exception as e:  # pylint: disable=broad-except
                                print(
                                    "ERROR: "
                                    + str(e)
                                    + " in packet "
                                    + str(num)
                                    + " at "
                                    + str(timestamp),
                                    file=sys.stderr,
                                )

        if use_polars:
            # Convert dtypes based on pcap_dtypes
            pl_schema = E2EPcap.get_polars_schema(pcap_dtypes)

            # for key in pcap_dtypes:
            #     if pcap_dtypes[key] not in ["object"]:
            #         pl_pcaparquet[key] = pl_pcaparquet[key].astype(pcap_dtypes[key])
            pl_pcaparquet = pl.DataFrame(pcap_dict_list, schema=pl.Schema(pl_schema))

            # Call callback for further processing
            for callback in self.post_callbacks:
                pl_pcaparquet = callback(pl_pcaparquet)

            # Drop not_decoded_data column if exists
            if "not_decoded_data" in pl_pcaparquet.columns:
                pl_pcaparquet = pl_pcaparquet.drop("not_decoded_data")

            if return_df:
                return pl_pcaparquet

            E2EPcap.write_dataframe(pl_pcaparquet, file_handle, outformat, close_fh)

        elif outformat == "json":
            print("]}", file=file_handle)

        if close_fh:
            file_handle.close()  # type: ignore
        else:
            sys.stdout.flush()

        return pl.DataFrame()
