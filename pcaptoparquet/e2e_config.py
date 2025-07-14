# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause
"""
This module contains the E2EConfig class which is used to hold the
configuration for the E2E Pcap class. This includes:
- Transport port to Protocol Decoding Callback mapping.
- Post processing callback function list.
"""
import importlib.util
import json
import os
from typing import Any, Callable, Optional, Tuple

from . import e2e_dns, e2e_http, e2e_https, e2e_ping, e2e_quic


class ProtocolDecoder:
    """
    Class to hold the protocol decoder functions.
    """

    def __init__(self, decode_cb: Callable[[Any, Any, Any], Optional[bytes]]) -> None:
        """
        Constructor for the ProtocolDecoder class.
        """
        self.decode = decode_cb

    def get_decode(self) -> Callable[[Any, Any, Any], Optional[bytes]]:
        """
        Get the decode function.
        """
        return self.decode


class E2EConfig:
    """
    Class to hold the configuration for the E2E Pcap class
    This includes:
    - Transport port to Protocol Decoding Callback mapping.
    - Post processing callback function list.
    """

    # Utility function to load a function from a file
    @staticmethod
    def load_function_from_file(
        file_path: str, function_name: str = "process_pcap_polars"
    ) -> Any:
        """
        Loads a function named 'process_pcap_polars' from the specified file.

        Args:
            file_path (str): The path to the file containing the function.

        Returns:
            callable: The loaded function.
        """
        spec = importlib.util.spec_from_file_location("module.name", file_path)
        if spec is None:
            raise ImportError(f"Cannot load module from {file_path}")
        module = importlib.util.module_from_spec(spec)
        if spec.loader is None:
            raise ImportError(f"Cannot load module from {file_path}")
        spec.loader.exec_module(module)
        func = getattr(module, function_name)
        if not callable(func):
            raise TypeError(f"{function_name} is not callable")
        return func

    @staticmethod
    def load_transport_protocol(
        tpport_to_prot: dict[str, Any],
        tp_config: dict[str, Any],
        decode_cb: Callable[[Any, Any, Any], Optional[bytes]],
    ) -> None:
        """
        Load the transport protocol configuration.
        """
        transports = ("TCP", "UDP", "SCTP")

        if tp_config["try_decode"]:
            for transport in tp_config["try_decode"]:
                if transport in transports:
                    # Add the decode function to the list of functions to try
                    tpport_to_prot[transport][0].append(decode_cb)

            for transport in transports:
                if transport in tp_config:
                    for port in tp_config[transport]:
                        tpport_to_prot[transport][port] = ProtocolDecoder(decode_cb)

            if "iterable" in tp_config:
                tpport_to_prot["iterable"].append(decode_cb)

    def load_mapping_from_file(self) -> Tuple[dict[str, Any], Any]:
        """
        Loads a mapping from the specified file.

        Returns:
            None.
        """
        # Read JSON file with mapping:
        # - module name:
        #   The module must have a function to decode/try_decode the protocol
        #   It can also include a function to add new fields to E2EPacket by default
        #   it should return values for the following fields:
        #   "app_type":"category",
        #   "app_session":"category",
        #   "app_seq":"UInt64",
        #   "app_request":"string",
        #   "app_response":"string",
        # - list of transport type and port tuples to assign to the module.
        # Additionally the config file can override the default ports for:
        # DNS, HTTP, HTTPS and QUIC protocols.
        # Processing functions can also be overwritten.

        transportport_to_protocol: dict[str, Any] = {}

        # First initialize PING, DNS, HTTP, HTTPS and QUIC
        # with default ports and processing functions
        # ICMP - ICMP6 Transport
        transportport_to_protocol["ICMP"] = ProtocolDecoder(e2e_ping.decode)

        applications = ("PING", "DNS", "HTTP", "HTTPS", "QUIC")

        app_mapping = {
            "PING": e2e_ping.decode,
            "DNS": e2e_dns.decode,
            "HTTP": e2e_http.decode,
            "HTTPS": e2e_https.decode,
            "QUIC": e2e_quic.decode,
        }

        # TCP Transport
        transportport_to_protocol["TCP"] = {}
        transportport_to_protocol["TCP"][0] = []
        transportport_to_protocol["TCP"][53] = ProtocolDecoder(e2e_dns.decode)
        transportport_to_protocol["TCP"][80] = ProtocolDecoder(e2e_http.decode)
        transportport_to_protocol["TCP"][8080] = ProtocolDecoder(e2e_http.decode)
        transportport_to_protocol["TCP"][443] = ProtocolDecoder(e2e_https.decode)

        # UDP Transport
        transportport_to_protocol["UDP"] = {}
        transportport_to_protocol["UDP"][0] = []
        transportport_to_protocol["UDP"][53] = ProtocolDecoder(e2e_dns.decode)
        transportport_to_protocol["UDP"][443] = ProtocolDecoder(e2e_quic.decode)

        # SCTP Transport
        transportport_to_protocol["SCTP"] = {}
        transportport_to_protocol["SCTP"][0] = []

        # Iterable protocols
        transportport_to_protocol["iterable"] = []

        mapping_with_modules: Any = None

        if self.configpath is not None:
            with open(self.configpath, "r", encoding="utf-8") as file:
                mapping_with_modules = json.load(file)

                # New applications
                for protocol in mapping_with_modules["protocols"]:
                    if protocol["protocol_name"] in applications:
                        raise ValueError(
                            f"Protocol {protocol['protocol_name']}"
                            + " to be defined in overrides section."
                        )
                    # Check if file exists
                    if not os.path.isfile(protocol["module_path"]):
                        raise FileNotFoundError(
                            f"File {protocol['module_path']} not found."
                        )

                    decode_cb = E2EConfig.load_function_from_file(
                        protocol["module_path"], "decode"
                    )

                    E2EConfig.load_transport_protocol(
                        transportport_to_protocol,
                        protocol["transport_protocols"],
                        decode_cb,
                    )

                # Existing applications (overrides)
                if "overrides" in mapping_with_modules:
                    for app in applications:
                        if app in mapping_with_modules["overrides"]:
                            protocol = mapping_with_modules["overrides"][app]
                            if not protocol["module_path"] or not os.path.isfile(
                                protocol["module_path"]
                            ):
                                decode_cb = app_mapping[app]
                            else:
                                decode_cb = E2EConfig.load_function_from_file(
                                    protocol["module_path"], "decode"
                                )

                            E2EConfig.load_transport_protocol(
                                transportport_to_protocol,
                                protocol["transport_protocols"],
                                decode_cb,
                            )

        return (transportport_to_protocol, mapping_with_modules)

    def __init__(
        self,
        transportport_to_protocol: Optional[
            dict[str, Any]  # Any stores mapping of transport port to protocol.
        ] = None,
        configpath: Optional[str] = None,
        callbacks: Optional[list[Callable[[Any], Any]]] = None,
        callbackpath: Optional[str] = None,
    ) -> None:
        """
        Constructor for the E2EConfig class.
        """
        self.configpath = configpath

        (
            self.transportport_to_protocol,
            self.mapping_with_modules,
        ) = self.load_mapping_from_file()

        if transportport_to_protocol:
            self.transportport_to_protocol = transportport_to_protocol

        if callbacks is None:
            callbacks = []
            if callbackpath:
                # Colon separated list of callback paths
                callbacklist = callbackpath.split(":")
                for callback in callbacklist:
                    callbacks.append(E2EConfig.load_function_from_file(callback))

        self.callbacks = callbacks

    def get_transport_port_cb(self) -> dict[str, Any]:
        """
        Get the transport port to protocol decoding callback mapping.
        """
        return self.transportport_to_protocol

    def get_post_callbacks(self) -> list[Callable[[Any], Any]]:
        """
        Get the post processing callback function list.
        """
        return self.callbacks

    def get_mapping_with_modules(self) -> Any:
        """
        Get the post processing callback function list.
        """
        return self.mapping_with_modules
