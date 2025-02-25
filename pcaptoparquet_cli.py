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

import polars as pl

from pcaptoparquet.e2e_config import E2EConfig
from pcaptoparquet.e2e_pcap import E2EPcap


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


def main() -> None:
    """
    Main function to convert pcap files to parquet format
    """
    my_parser = init_parser()

    args = my_parser.parse_args()

    e2e_output = args.output

    e2e_config = E2EConfig(configpath=args.config, callbackpath=args.callback)

    if not args.input:
        # Throw an error if multiprocessing is requested without input file
        if args.multiprocessing:
            my_parser.error("Multiprocessing requires an input file to be specified.")

        json_tags = tags_to_json({}, args.tags)

        E2EPcap(
            json_tags,
            args.point,
            None,  # input file,
            e2e_config,
            pcapng=args.pcapng,
            parallel=args.multiprocessing,
        ).export(output=e2e_output, outformat=args.format)

    else:
        # Use polar dataframes for processing
        with pl.StringCache():
            pl_list: list[pl.DataFrame] = []
            for e2e_input in args.input:
                # Check if input file exists
                if not os.path.exists(e2e_input):
                    my_parser.error(f"Input file '{e2e_input}' not found.")

                # Get the directory and name of the input file
                (pcap_dir, pcap_name) = os.path.split(e2e_input)

                json_tags = tags_to_json(
                    {"filename": pcap_name, "path": pcap_dir}, args.tags
                )

                if not args.output:
                    # bytes([0x1F, 0x8B, 0x08]): "gz",
                    # bytes([0x42, 0x5A, 0x68]): "bz2",
                    # bytes([0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]): "xz",
                    # Remove the gzip, bzip2, and xz extensions
                    # and replace pcap or pcapng with the output format
                    e2e_output, ext = os.path.splitext(e2e_input)
                    if ext in [".gz", ".bz2", ".xz"]:
                        e2e_output, ext = os.path.splitext(e2e_output)
                    e2e_output = e2e_output + "." + args.format

                    # Generate one output file for each input file
                    E2EPcap(
                        json_tags,
                        args.point,
                        e2e_input,  # input file
                        e2e_config,
                        pcapng=args.pcapng,
                        parallel=args.multiprocessing,
                    ).export(output=e2e_output, outformat=args.format)
                else:
                    if len(args.input) > 1:
                        # Collect all the polars dataframes in a list
                        # print input file name to track progress
                        print(f"Processing {e2e_input}")
                        pl_list.append(
                            E2EPcap(
                                json_tags,
                                args.point,
                                e2e_input,  # input file
                                e2e_config,
                                pcapng=args.pcapng,
                                parallel=args.multiprocessing,
                            ).export(
                                output=e2e_output, outformat=args.format, return_df=True
                            )
                        )
                    else:
                        E2EPcap(
                            json_tags,
                            args.point,
                            e2e_input,  # input file
                            e2e_config,
                            pcapng=args.pcapng,
                            parallel=args.multiprocessing,
                        ).export(output=e2e_output, outformat=args.format)

            if len(pl_list) > 0:
                file_handle = E2EPcap.get_output_buffer(args.format, e2e_output, True)
                pl_df = pl.concat(pl_list)
                E2EPcap.write_dataframe(pl_df, file_handle, args.format, True)


if __name__ == "__main__":
    main()
