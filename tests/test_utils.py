"""
Utilities for testing
"""

import cProfile
import linecache
import os
import pstats
import tracemalloc
from time import process_time
from typing import Any, Optional

from pcaptoparquet import E2EConfig, E2EPcap


def display_top(
    snapshot: Any, key_type: str = "lineno", limit: int = 10, file: Optional[Any] = None
) -> None:
    """Display the top lines of memory usage"""
    snapshot = snapshot.filter_traces(
        (
            tracemalloc.Filter(False, "<frozen importlib._bootstrap>"),
            tracemalloc.Filter(False, "<unknown>"),
        )
    )
    top_stats = snapshot.statistics(key_type)

    print(f"Top {limit} lines", file=file)
    for index, stat in enumerate(top_stats[:limit], 1):
        frame = stat.traceback[0]
        print(
            f"#{index}: {frame.filename}:{frame.lineno}: {stat.size / 1024:.1f} KiB",
            file=file,
        )
        line = linecache.getline(frame.filename, frame.lineno).strip()
        if line:
            print(f"    {line}", file=file)

    other = top_stats[limit:]
    if other:
        size = sum(stat.size for stat in other)
        print(f"{len(other)} other: {size / 1024:.1f} KiB", file=file)
    total = sum(stat.size for stat in top_stats)
    print(f"Total allocated size: {total / 1024:.1f} KiB", file=file)


def configure_dirs() -> dict[str, str]:
    """Configure the directories for the tests"""
    wdir = os.path.join(os.getcwd(), "tests")  # os.path.dirname(__file__)
    ddir = os.path.join(wdir, "data")
    odir = os.path.join(wdir, "out")
    bdir = os.path.join(wdir, "benchmark")
    cdir = os.path.join(wdir, "config")
    return {"ddir": ddir, "odir": odir, "bdir": bdir, "cdir": cdir}


def process_e2e(
    input_file: str,
    config: E2EConfig,
    point: str,
    odir: str,
    outformat: str = "parquet",
    pktnum: int = 0,
    out: bool = True,
    parallel: bool = False,
) -> None:
    """Open up a test pcap file and print out the packets"""
    pcap_name = os.path.basename(input_file)
    if out:
        E2EPcap(
            {
                "pcap_name": pcap_name,
            },
            point,
            input_file,
            config,
            parallel=parallel,
        ).export(
            output=os.path.join(odir, os.path.splitext(pcap_name)[0] + "." + outformat),
            outformat=outformat,
            pktnum=pktnum,
        )
    else:
        E2EPcap(
            {
                "pcap_name": pcap_name,
            },
            point,
            input_file,
            config,
            parallel=parallel,
        ).export(output="", outformat=outformat, pktnum=pktnum)


def generate_outputs(
    input_file: str,
    config: E2EConfig,
    point: str,
    odir: str,
    formats: Optional[list[str]] = None,
    parallel: bool = False,
    print_profile: bool = False,
) -> None:
    """Generate outputs for the test pcap file"""
    if formats is None:
        formats = ["txt", "json", "parquet"]
    os.makedirs(odir, exist_ok=True)
    pcap_name = os.path.basename(input_file)
    input_size = os.path.getsize(input_file)
    for outformat in formats:
        output = os.path.join(odir, os.path.splitext(pcap_name)[0] + "." + outformat)
        if os.path.exists(output):
            os.remove(output)

        with cProfile.Profile() as pr:
            tracemalloc.start()
            start_time = process_time()
            process_e2e(
                input_file, config, point, odir, outformat=outformat, parallel=parallel
            )
            elapsed_time = process_time() - start_time
            snapshot = tracemalloc.take_snapshot()
            tracemalloc.stop()

        assert os.path.exists(output)
        output_size = os.path.getsize(output)
        compression_ratio = output_size / input_size * 100
        if elapsed_time > 0.0:
            processing_speed = input_size / elapsed_time
        else:
            processing_speed = (
                0  # This is an error only occurring in Windows environment.
            )

        with open(os.path.join(odir, "test_E2EPcap.log"), "a", encoding="utf-8") as f:
            print(
                f"Performance evaluation for {input_file} format {outformat}:", file=f
            )
            print(f"    Input file size:    {input_size} bytes", file=f)
            print(f"    Output file size:   {output_size} bytes", file=f)
            print(f"    Compression ratio:  {compression_ratio:.2f}%", file=f)
            print(f"    Elapsed time:       {elapsed_time:.2f} seconds", file=f)
            print(
                f"    Processing speed:   {processing_speed:.2f} bytes/second", file=f
            )
            print("", file=f)
            if print_profile:
                print(f"Profile result for {input_file} format {outformat}:", file=f)

            profile_result = pstats.Stats(pr, stream=f)
            profile_result.sort_stats(pstats.SortKey.TIME)
            if print_profile:
                profile_result.print_stats()
                print("", file=f)
                display_top(snapshot, file=f)

            profile_result.dump_stats(
                os.path.join(
                    odir,
                    (os.path.splitext(pcap_name)[0] + "." + outformat + ".profile"),
                )
            )
