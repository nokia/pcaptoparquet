#!/usr/bin/env python

# Copyright 2025 Nokia
# Licensed under the BSD 3-Clause License.
# SPDX-License-Identifier: BSD-3-Clause
"""
script.py
~~~~~~~~~~~~~~~~
This script converts pcap files to parquet format. It takes input file, output file,
additional tags, point type, and output format as command line arguments.

Usage:
    python script.py [-h] [-n] [-m]
                     [-i INPUT [INPUT ...]]
                     [-o OUTPUT]
                     [-t TAGS [TAGS ...]]
                     [-p {Client,Network,Server,Unknown}]
                     [-f {parquet,txt,json}]
                     [-c CALLBACK[:CALLBACK ...]]
                     [-g CONFIG]

Options:
    -h, --help                  Show this help message and exit.
    -v, --version               Show version and exit.
    -i INPUT, --input INPUT     Input file or files. Standard input is used
                                if not provided.
    -o OUTPUT, --output OUTPUT  Output file. Standard output is used
                                if not provided and input is standard input.
    -t TAGS [TAGS ...], --tags TAGS [TAGS ...]
                                Additional tags to be added to the output in
                                'key:value' format. Multiple tags can be provided.
    -p {Client,Network,Server,Unknown}, --point {Client,Network,Server,Unknown}
                                Point type. Default is 'Unknown'.
    -f {txt,json,parquet}, --format {parquet,txt,json}
                                Output format. Default is 'parquet'.
    -n, --pcapng                Use pcapng format for input file.
    -c CALLBACK[:CALLBACK ...], --callback CALLBACK[:CALLBACK ...]
                                Filenames with callback function for post-processing.
    -m, --multiprocessing       Use pcapparallel processing.
    -g CONFIG, --config CONFIG  JSON Configuration file for protocol decoding.
"""
import argparse
import importlib.metadata
import os
import sys
from typing import Optional

import polars as pl

from pcaptoparquet import E2EConfig, E2EPcap


def init_parser() -> argparse.ArgumentParser:
    """
    Initialize the argument parser
    Returns:
        parser: ArgumentParser object
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=importlib.metadata.version("pcaptoparquet"),
    )
    parser.add_argument(
        "-i",
        "--input",
        action="store",
        nargs="+",
        help="Input file or files. Standard input is used if not provided.",
    )
    parser.add_argument(
        "-o",
        "--output",
        action="store",
        help=(
            "Output file. Standard output is used if not provided and "
            + "input is standard input."
        ),
    )
    parser.add_argument(
        "-t",
        "--tags",
        action="store",
        nargs="+",
        help=(
            "Additional tags to be added to the output in 'key:value' "
            + "format. Multiple tags can be provided: --tags 'kk1:vv1' "
            + "'kk2:vv2' ... 'kkn:vvn'"
        ),
    )
    parser.add_argument(
        "-p",
        "--point",
        action="store",
        choices=["Client", "Network", "Server", "Unknown"],
        default="Unknown",
    )
    parser.add_argument(
        "-f",
        "--format",
        action="store",
        choices=["parquet", "txt", "json"],
        default="parquet",
    )
    parser.add_argument(
        "-n",
        "--pcapng",
        action="store_true",
        help="Force PCAPNG format for input file. Needed for stdin.",
    )
    parser.add_argument(
        "-m",
        "--multiprocessing",
        action="store_true",
        help=(
            "Use pcapparallel processing. "
            + "Disabled by default and not compatible with stdin."
        ),
    )
    parser.add_argument(
        "-c",
        "--callback",
        action="store",
        help=(
            "Filenames with callback function for post-processing. "
            + "Multiple callbacks can be provided."
        ),
    )
    parser.add_argument(
        "-g",
        "--config",
        action="store",
        help="JSON Configuration file for protocol decoding.",
    )

    return parser


def tags_to_json(json_tags: dict[str, str], tags: list[str]) -> dict[str, str]:
    """
    Convert tags to json format
    """
    if tags:
        ii = len(json_tags)
        for tagstr in tags:
            if tagstr.count(":") == 1:
                ss = tagstr.split(":")
                json_tags["tag_" + ss[0]] = ss[1]
            else:
                json_tags["tag_" + str(ii)] = tagstr
            ii = ii + 1
    return json_tags


def get_tags_from_file(
    tags: list[str], e2e_input: Optional[str] = None
) -> dict[str, str]:
    """
    Get tags from the input file
    """
    if not e2e_input:
        return tags_to_json({}, tags)

    # Get the directory and name of the input file
    (pcap_dir, pcap_name) = os.path.split(e2e_input)

    return tags_to_json({"filename": pcap_name, "path": pcap_dir}, tags)


def get_output_from_inputs(
    e2e_format: str,
    e2e_input: Optional[str] = None,
    e2e_output: Optional[str] = None,
) -> Optional[str]:
    """
    Get the output file from the input file
    """
    if not e2e_input:
        return e2e_output

    if not e2e_output:
        # Remove the gzip, bzip2, and xz extensions
        # and replace pcap or pcapng with the output format
        e2e_output, ext = os.path.splitext(e2e_input)
        if ext in [".gz", ".bz2", ".xz"]:
            e2e_output, ext = os.path.splitext(e2e_output)
        e2e_output = e2e_output + "." + e2e_format

    return e2e_output


def main() -> None:
    """
    Main function to convert pcap files to parquet format
    """
    my_parser = init_parser()

    args = my_parser.parse_args()

    e2e_config = E2EConfig(configpath=args.config, callbackpath=args.callback)

    # None or one input file
    if not args.input or len(args.input) == 1:

        # Check if multiprocessing is requested without input file
        if not args.input:
            # Standard input special case
            if args.multiprocessing:
                sys.exit("Multiprocessing requires an input file to be specified.")

            e2e_input = None
        else:
            e2e_input = args.input[0]

        try:
            E2EPcap(
                get_tags_from_file(args.tags, e2e_input),
                args.point,
                e2e_input,  # input file,
                e2e_config,
                pcapng=args.pcapng,
                parallel=args.multiprocessing,
            ).export(
                output=get_output_from_inputs(args.format, e2e_input, args.output),
                outformat=args.format,
            )
        except ValueError as err:
            if not args.input:
                sys.exit(f"Standard input: {err}")
            else:
                sys.exit(f"Input file '{e2e_input}' {err}")

    else:
        # Use polar dataframes for processing
        with pl.StringCache():

            pl_list: list[pl.DataFrame] = []

            total_files = len(args.input)
            for index, e2e_input in enumerate(args.input):
                percentage = (index + 1) / total_files * 100
                print(f"Processing [{percentage:.2f}%] {e2e_input} ")

                # Check if input file exists
                if not os.path.exists(e2e_input):
                    my_parser.error(f"Input file '{e2e_input}' not found.")

                try:
                    e2e_pcap = E2EPcap(
                        get_tags_from_file(args.tags, e2e_input),
                        args.point,
                        e2e_input,  # input file
                        e2e_config,
                        pcapng=args.pcapng,
                        parallel=args.multiprocessing,
                    )

                    if args.output:
                        pl_list.append(
                            e2e_pcap.export(
                                output=None, outformat=args.format, return_df=True
                            )
                        )
                    else:
                        e2e_pcap.export(
                            output=get_output_from_inputs(args.format, e2e_input, None),
                            outformat=args.format,
                            return_df=False,
                        )
                except ValueError as err:
                    sys.exit(f"Input file '{e2e_input}' {err}")

            if len(pl_list) > 0:
                file_handle = E2EPcap.get_output_buffer(args.format, args.output, True)
                pl_df = pl.concat(pl_list)
                E2EPcap.write_dataframe(pl_df, file_handle, args.format, True)


if __name__ == "__main__":
    main()
