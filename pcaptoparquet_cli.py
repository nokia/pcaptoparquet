#!/usr/bin/env python

# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause
"""
pcaptoparquet_cli.py
~~~~~~~~~~~~~~~~~~~~
This script converts pcap files to parquet format. It takes input file, output file,
additional tags, point type, and output format as command line arguments.
It is a simple example of how to use the pcaptoparquet library in a command line interface.
Behavior can be extended by:
    * Adding more command line arguments in the `add_argument_cb` function.
    * Specifying a custom configuration file by passing the `configpath` argument.
    * Modifying post-processing behavior by passing a custom callback function to
      the `callbackpath` argument.
"""
import argparse

from pcaptoparquet import E2ECli


def dummy_argument_cb(parser: argparse.ArgumentParser) -> argparse.ArgumentParser:
    """
    Add command line arguments to the parser.
    Args:
        parser (argparse.ArgumentParser): The argument parser to add arguments to.
    """
    return parser


def main() -> None:
    """
    Main function to convert pcap files to parquet format
    """
    E2ECli(add_argument_cb=dummy_argument_cb, configpath=None, callbackpath=None).run()


if __name__ == "__main__":
    main()
