"""
pcaptoparquet command line tool unit tests
"""

import os
import subprocess
from dataclasses import dataclass
from typing import Optional

# usage: pcaptoparquet [-h] [-v] [-i INPUT [INPUT ...]] [-o OUTPUT]
#                      [-t TAGS [TAGS ...]]
#                      [-p {Client,Network,Server,Unknown}]
#                      [-f {parquet,txt,json}]
#                      [-n] [-m] [-c CALLBACK]
#                      [-g CONFIG]
#
# options:
#   -h, --help            show this help message and exit
#   -v, --version         show program's version number and exit
#   -i INPUT [INPUT ...], --input INPUT [INPUT ...]
#                         Input file or files. Standard input is used if not provided.
#   -o OUTPUT, --output OUTPUT
#                         Output file. Standard output is used if not provided and
#                         input is standard input.
#   -t TAGS [TAGS ...], --tags TAGS [TAGS ...]
#                         Additional tags to be added to the output in 'key:value'
#                         format. Multiple tags can be provided:
#                         --tags 'kk1:vv1' 'kk2:vv2' ... 'kkn:vvn'
#   -p {Client,Network,Server,Unknown}, --point {Client,Network,Server,Unknown}
#   -f {parquet,txt,json}, --format {parquet,txt,json}
#   -n, --pcapng          Force PCAPNG format for input file. Needed for stdin.
#   -m, --multiprocessing
#                         Use pcapparallel processing. Disabled by default and
#                         not compatible with stdin.
#   -c CALLBACK, --callback CALLBACK
#                         Filenames with callback function for post-processing.
#                         Multiple callbacks can be provided.
#   -g CONFIG, --config CONFIG
#                         JSON Configuration file for protocol decoding.


def are_binary_files_identical(file1: str, file2: str) -> None:
    """
    Check if two files are identical
    """
    result = subprocess.run(
        ["diff", "--binary", file1, file2], capture_output=True, text=True, check=False
    )
    assert (
        result.returncode == 0
    ), f"Files {file1} and {file2} are not identical: {result.stdout}"


def run_command(
    cmd: str, filein: Optional[str], fileout: str, build: bool = False
) -> None:
    """
    Run a command and check that the output file exists
    """
    if filein:
        assert os.path.exists(filein)
    odir = os.path.dirname(fileout)
    os.makedirs(odir, exist_ok=True)
    if build:
        os.system("python -m build")
        os.system("python -m pip install .")
    if os.path.exists(fileout):
        os.system(f"rm {fileout}")
    os.system(cmd)
    assert os.path.exists(fileout)
    assert os.path.getsize(fileout) > 0


def run_command_check_err(cmd: str, error: str) -> None:
    """
    Run an invalid command and that it returns an error
    """
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True, check=False
    )
    assert result.returncode > 0
    # error is contained in the stderr
    assert error in result.stderr


# Test pcaptoparquet.py -h returns help message
def test_help_message() -> None:
    """
    Test that the help message is displayed
    """
    filein = None
    output = os.path.join("tests", "out", "99_others", "help_message.txt")
    cmd = f"pcaptoparquet -h > {output}"
    run_command(cmd, filein, output, build=True)


@dataclass
class FileInfo:
    """
    Dataclass to store file information
    """

    prefix: str = "example"
    path: str = os.path.join("tests", "data", "00_functional", "99_others")
    ext: str = ".pcap"


@dataclass
class OutInfo:
    """
    Dataclass to store output information
    """

    path: str = os.path.join("tests", "out", "99_others")
    ext: str = ".parquet"


@dataclass
class SuffixInfo:
    """
    Dataclass to store suffix information
    """

    format: str = ""
    option: str = ""


def run_basic_input(
    file: FileInfo = FileInfo(),
    out: OutInfo = OutInfo(),
    options: str = "",
    suffix: SuffixInfo = SuffixInfo(),
) -> None:
    """
    Run a explicit input file processing with implicit and explicit output.
    """
    # First we run the implicit output version
    # pcaptoparquet will create a file with the same name as the input file
    # but with the extension changed to out_ext (parquet by default)
    filein = os.path.join(f"{file.path}", f"{file.prefix}{suffix.format}{file.ext}")
    output = os.path.join(f"{file.path}", f"{file.prefix}{suffix.format}{out.ext}")
    cmd = f"pcaptoparquet {options} -i {filein}"
    run_command(cmd, filein, output, build=False)

    input_tmp = output
    output_1 = os.path.join(
        f"{out.path}", f"{file.prefix}{suffix.option}{suffix.format}{out.ext}"
    )
    cmd = f"mv {input_tmp} {output_1}"
    run_command(cmd, input_tmp, output_1, build=False)

    output_2 = os.path.join(
        f"{out.path}", f"{file.prefix}_explicit{suffix.option}{suffix.format}{out.ext}"
    )
    cmd = f"pcaptoparquet {options} -i {filein} -o {output_2}"
    run_command(cmd, filein, output_2, build=False)

    are_binary_files_identical(output_1, output_2)


def test_basic_input_pcap() -> None:
    """
    Run a basic pcap file processing with implicit and explicit output.
    """
    run_basic_input()


def test_basic_input_pcap_gz() -> None:
    """
    Run a basic gz pcap file processing with implicit and explicit
    """
    run_basic_input(file=FileInfo(ext=".pcap.gz"), suffix=SuffixInfo(format="_gz"))


def test_basic_input_pcapng() -> None:
    """
    Run a basic pcapng file processing with implicit and explicit output.
    """
    run_basic_input(file=FileInfo(ext=".pcapng"), suffix=SuffixInfo(format="_ng"))


def test_basic_input_pcapng_gz() -> None:
    """
    Run a basic pcapng gz file processing with implicit and explicit output.
    """
    run_basic_input(file=FileInfo(ext=".pcapng.gz"), suffix=SuffixInfo(format="_ng_gz"))


def test_mp_input_pcap() -> None:
    """
    Run a basic pcap file multiprocessing with explitcit and implicit output.
    """
    run_basic_input(options="-m", suffix=SuffixInfo(option="_mp"))
    prev_out = os.path.join("tests", "out", "99_others", "example.parquet")
    if os.path.exists(prev_out):
        are_binary_files_identical(
            os.path.join("tests", "out", "99_others", "example.parquet"),
            os.path.join("tests", "out", "99_others", "example_mp.parquet"),
        )


def test_mp_input_pcap_gz() -> None:
    """
    Run a basic pcap gz file multiprocessing with explitcit and implicit output.
    """
    run_basic_input(
        file=FileInfo(ext=".pcap.gz"),
        options="-m",
        suffix=SuffixInfo(format="_gz", option="_mp"),
    )
    prev_out = os.path.join("tests", "out", "99_others", "example_gz.parquet")
    if os.path.exists(prev_out):
        are_binary_files_identical(
            os.path.join("tests", "out", "99_others", "example_gz.parquet"),
            os.path.join("tests", "out", "99_others", "example_mp_gz.parquet"),
        )


def test_mp_input_pcapng() -> None:
    """
    Run a basic pcapng file multiprocessing with explitcit and implicit output.
    """
    run_basic_input(
        file=FileInfo(ext=".pcapng"),
        options="-m",
        suffix=SuffixInfo(format="_ng", option="_mp"),
    )
    prev_out = os.path.join("tests", "out", "99_others", "example_ng.parquet")
    if os.path.exists(prev_out):
        are_binary_files_identical(
            os.path.join("tests", "out", "99_others", "example_ng.parquet"),
            os.path.join("tests", "out", "99_others", "example_mp_ng.parquet"),
        )


def test_mp_input_pcapng_gz() -> None:
    """
    Run a basic pcapng gz file multiprocessing with explitcit and implicit output.
    """
    run_basic_input(
        file=FileInfo(ext=".pcapng.gz"),
        options="-m",
        suffix=SuffixInfo(format="_ng_gz", option="_mp"),
    )
    prev_out = os.path.join("tests", "out", "99_others", "example_ng_gz.parquet")
    if os.path.exists(prev_out):
        are_binary_files_identical(
            os.path.join("tests", "out", "99_others", "example_ng_gz.parquet"),
            os.path.join("tests", "out", "99_others", "example_mp_ng_gz.parquet"),
        )


def run_stdin_input(
    file: FileInfo = FileInfo(),
    out: OutInfo = OutInfo(),
    options: str = "",
    suffix: SuffixInfo = SuffixInfo(),
) -> None:
    """
    Run standard input processing with implicit and explicit output.
    """
    # First we run the explicit output version
    filein = os.path.join(f"{file.path}", f"{file.prefix}{suffix.format}{file.ext}")
    output_1 = os.path.join(
        f"{out.path}",
        f"{file.prefix}_stdin_explicit{suffix.option}{suffix.format}{out.ext}",
    )
    cmd = f"pcaptoparquet {options} -o {output_1} < {filein}"

    run_command(cmd, filein, output_1, build=False)

    output_2 = os.path.join(
        f"{out.path}",
        f"{file.prefix}_stdin_stdout{suffix.option}{suffix.format}{out.ext}",
    )
    cmd = f"pcaptoparquet {options} < {filein} > {output_2}"
    run_command(cmd, filein, output_2, build=False)

    are_binary_files_identical(output_1, output_2)


def test_stdin_input_pcap() -> None:
    """
    Run standard input pcap processing with implicit and explicit output.
    """
    run_stdin_input()


def test_stdin_input_pcapng() -> None:
    """
    Run standard input pcapng processing with implicit and explicit output.
    """
    run_stdin_input(
        file=FileInfo(ext=".pcapng"),
        options="--pcapng",
        suffix=SuffixInfo(format="_ng"),
    )


def test_mp_stdin_input_pcap() -> None:
    """
    Standard input pcap multiprocessing error.
    """
    expected_error = "Multiprocessing requires an input file to be specified."
    implicit_input = os.path.join(
        "tests", "data", "00_functional", "99_others", "example.pcap"
    )
    run_command_check_err(
        f"pcaptoparquet -m < {implicit_input}",
        expected_error,
    )


def test_mp_stdin_input_pcapng() -> None:
    """
    Standard input pcapng multiprocessing error.
    """
    expected_error = "Multiprocessing requires an input file to be specified."
    implicit_input = os.path.join(
        "tests", "data", "00_functional", "99_others", "example_ng.pcapng"
    )
    run_command_check_err(
        f"pcaptoparquet -m < {implicit_input}",
        expected_error,
    )


#   -f {txt,json,parquet}, --format {txt,json,parquet}
def check_txt_file(
    filename: str, check_col: bool = True, num_lines: str = "22223"
) -> None:
    """
    Check the number of lines and columns in a txt file
    """
    # Check that the number of lines is correct
    result = subprocess.run(
        f"wc -l {filename}", shell=True, capture_output=True, text=True, check=False
    )
    assert result.returncode == 0
    assert result.stdout.split()[0] == num_lines
    if check_col:
        # Check that all lines have the same number of fields
        result = subprocess.run(
            f"awk -F'|' '{{print NF}}' {filename} | sort -nu | wc -l",
            shell=True,
            capture_output=True,
            text=True,
            check=False,
        )
        assert result.returncode == 0
        assert result.stdout.split()[0] == "1"


def same_col_num(file_1: str, file_2: str) -> None:
    """
    Check that two txt files have the same number of columns
    """
    # Check that all lines have the same number of fields
    result_1 = subprocess.run(
        f"awk -F'|' '{{print NF}}' {file_1} | sort -nu",
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result_1.returncode == 0
    result_2 = subprocess.run(
        f"awk -F'|' '{{print NF}}' {file_2} | sort -nu",
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result_2.returncode == 0
    # Check that the number of fields is the same
    assert result_1.stdout.split()[0] == result_2.stdout.split()[0]


def test_basic_input_pcap_txt() -> None:
    """
    Run a basic pcap file processing to txt format
    """
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options="-f txt",
    )
    output_file = os.path.join("tests", "out", "99_others", "example.txt")
    check_txt_file(output_file)


def test_mp_input_pcap_txt() -> None:
    """
    Run a basic pcap file multiprocessing to txt format
    """
    run_basic_input(
        out=OutInfo(ext=".txt"), options="-m -f txt", suffix=SuffixInfo(option="_mp")
    )
    output_file = os.path.join("tests", "out", "99_others", "example_mp.txt")
    check_txt_file(output_file)
    prev_file = os.path.join("tests", "out", "99_others", "example.txt")
    if os.path.exists(prev_file):
        same_col_num(prev_file, output_file)


def run_multi_input(
    file: FileInfo = FileInfo(),
    out: OutInfo = OutInfo(),
    options: str = "",
    suffix: SuffixInfo = SuffixInfo(),
) -> None:
    """
    Run a multi input file processing with implicit and explicit output.
    """
    # First we run the implicit output version
    # pcaptoparquet will create a file with the same name as the input file
    # but with the extension changed to out_ext (parquet by default)
    filein = os.path.join(f"{file.path}", f"{file.prefix}{suffix.format}_part*")
    output = os.path.join(
        f"{file.path}", f"{file.prefix}{suffix.format}_part*{out.ext}"
    )
    cmd = f"pcaptoparquet {options} -i {filein}"
    os.system(f"rm -f {output}")
    os.system(cmd)

    input_tmp = output
    output_1 = os.path.join(
        f"{out.path}", f"{file.prefix}{suffix.option}{suffix.format}_part*{out.ext}"
    )
    os.system(f"rm -f {output_1}")
    cmd = f"mv {input_tmp} {out.path}"
    os.system(cmd)

    output_2 = os.path.join(
        f"{out.path}",
        f"{file.prefix}_explicit{suffix.option}{suffix.format}_all{out.ext}",
    )
    cmd = f"pcaptoparquet {options} -i {filein} -o {output_2}"
    os.system(f"rm -f {output_2}")
    os.system(cmd)


def test_multi_input_txt() -> None:
    """
    Run multi input file processing to txt format
    """
    run_multi_input(out=OutInfo(ext=".txt"), options="-f txt")
    check_txt_file(os.path.join("tests", "out", "99_others", "example_part_01.txt"))
    check_txt_file(os.path.join("tests", "out", "99_others", "example_part_02.txt"))
    check_txt_file(
        os.path.join("tests", "out", "99_others", "example_explicit_all.txt"),
        num_lines="44445",
    )


def test_multi_input_gz_txt() -> None:
    """
    Run multi input gz file processing to txt format
    """
    run_multi_input(
        suffix=SuffixInfo(format="_gz"), out=OutInfo(ext=".txt"), options="-f txt"
    )
    check_txt_file(os.path.join("tests", "out", "99_others", "example_gz_part_01.txt"))
    check_txt_file(os.path.join("tests", "out", "99_others", "example_gz_part_02.txt"))
    check_txt_file(
        os.path.join("tests", "out", "99_others", "example_explicit_gz_all.txt"),
        num_lines="44445",
    )


def test_basic_input_pcap_json() -> None:
    """
    Run a basic pcap file processing to json format
    """
    run_basic_input(out=OutInfo(ext=".json"), options="-f json")
    check_txt_file(
        os.path.join("tests", "out", "99_others", "example.json"),
        check_col=False,
        num_lines="22224",
    )


def test_mp_input_pcap_json() -> None:
    """
    Run a basic pcap file multiprocessing to json format
    """
    run_basic_input(
        out=OutInfo(ext=".json"), options="-m -f json", suffix=SuffixInfo(option="_mp")
    )
    check_txt_file(
        os.path.join("tests", "out", "99_others", "example_mp.json"),
        check_col=False,
        num_lines="22222",
    )


#  One test for each collection point type
#   -p {Client,Network,Server,Unknown}, --point {Client,Network,Server,Unknown}
def check_collection_type(filename: str, ctype: str, pos: int = 3) -> None:
    """
    Check that all lines have the same number of fields
    """
    # Check that all lines have the same number of fields
    result = subprocess.run(
        f"grep {ctype} {filename} | awk -F'|' '{{print ${pos}}}' | uniq",
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.split()[0] == ctype


def test_basic_input_pcap_p_default() -> None:
    """
    Run a basic pcap file processing with default collection type (Unknown).
    """
    run_basic_input(
        out=OutInfo(ext=".txt"), options="-f txt", suffix=SuffixInfo(option="_default")
    )
    check_collection_type(
        os.path.join("tests", "out", "99_others", "example_default.txt"), "Unknown"
    )


def test_basic_input_pcap_p_client() -> None:
    """
    Run a basic pcap file processing with collection type Client.
    """
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options="-f txt -p Client",
        suffix=SuffixInfo(option="_client"),
    )
    check_collection_type(
        os.path.join("tests", "out", "99_others", "example_client.txt"), "Client"
    )


def test_basic_input_pcap_p_network() -> None:
    """
    Run a basic pcap file processing with collection type Network.
    """
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options="-f txt -p Network",
        suffix=SuffixInfo(option="_network"),
    )
    check_collection_type(
        os.path.join("tests", "out", "99_others", "example_network.txt"), "Network"
    )


def test_basic_input_pcap_p_server() -> None:
    """
    Run a basic pcap file processing with collection type Server.
    """
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options="-f txt -p Server",
        suffix=SuffixInfo(option="_server"),
    )
    check_collection_type(
        os.path.join("tests", "out", "99_others", "example_server.txt"), "Server"
    )


def test_basic_input_pcap_p_unknown() -> None:
    """
    Run a basic pcap file processing with collection type Unknown.
    """
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options="-f txt -p Unknown",
        suffix=SuffixInfo(option="_unknown"),
    )
    check_collection_type(
        os.path.join("tests", "out", "99_others", "example_unknown.txt"), "Unknown"
    )


def test_basic_input_pcap_p_error() -> None:
    """
    Run a basic pcap file processing with an invalid collection type.
    """
    expected_error = "argument -p/--point: invalid choice:"

    input_file = os.path.join(
        "tests", "data", "00_functional", "99_others", "example.pcap"
    )
    run_command_check_err(
        f"pcaptoparquet -f txt -p Error {input_file}",
        expected_error,
    )


#   -t TAGS [TAGS ...], --tags TAGS [TAGS ...]
def check_column_values(filename: str, tag: str, value: str, pos: int) -> None:
    """
    Check that all lines have value at the specified position
    """
    # Check that all lines have the same number of fields
    result = subprocess.run(
        f"head -1 {filename} | awk -F'|' '{{print ${pos}}}'",
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.split()[0] == tag

    # Check that all lines have the same number of fields
    result = subprocess.run(
        f"grep {value} {filename} | awk -F'|' '{{print ${pos}}}' | uniq",
        shell=True,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0
    assert result.stdout.split()[0] == value


def test_basic_input_pcap_tag_default() -> None:
    """
    Run a basic pcap file processing with default tags.
    """
    run_basic_input(
        out=OutInfo(ext=".txt"), options="-f txt", suffix=SuffixInfo(option="_default")
    )
    output_file = os.path.join("tests", "out", "99_others", "example_default.txt")
    check_column_values(output_file, "filename", "example.pcap", pos=4)
    input_path = os.path.join("tests", "data", "00_functional", "99_others")
    check_column_values(
        output_file,
        "path",
        input_path,
        pos=5,
    )


# pcaptoparquet -t "kkk:vvv"
def test_basic_input_pcap_one_tag() -> None:
    """
    Run a basic pcap file processing with one tag.
    """
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options="-f txt -t 'kkk:vvv'",
        suffix=SuffixInfo(option="_one_tag"),
    )
    output_file = os.path.join("tests", "out", "99_others", "example_one_tag.txt")
    check_column_values(output_file, "filename", "example.pcap", pos=4)
    input_path = os.path.join("tests", "data", "00_functional", "99_others")
    check_column_values(
        output_file,
        "path",
        input_path,
        pos=5,
    )
    check_column_values(output_file, "tag_kkk", "vvv", pos=6)


# pcaptoparquet -t "kkk:vvv" "KKK:VVV"
def test_basic_input_pcap_two_tags() -> None:
    """
    Run a basic pcap file processing with two tags.
    """
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options="-f txt -t 'kkk:vvv' 'KKK:VVV'",
        suffix=SuffixInfo(option="_two_tags"),
    )
    output_file = os.path.join("tests", "out", "99_others", "example_two_tags.txt")
    check_column_values(output_file, "filename", "example.pcap", pos=4)
    input_path = os.path.join("tests", "data", "00_functional", "99_others")
    check_column_values(
        output_file,
        "path",
        input_path,
        pos=5,
    )
    check_column_values(output_file, "tag_kkk", "vvv", pos=6)
    check_column_values(output_file, "tag_KKK", "VVV", pos=7)


# pcaptoparquet -t "nokey"
def test_basic_input_pcap_tag_no_key() -> None:
    """
    Run a basic pcap file processing with tag no key.
    """
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options="-f txt -t 'nokey'",
        suffix=SuffixInfo(option="_tag_no_key"),
    )
    output_file = os.path.join("tests", "out", "99_others", "example_tag_no_key.txt")
    check_column_values(output_file, "filename", "example.pcap", pos=4)
    input_path = os.path.join("tests", "data", "00_functional", "99_others")
    check_column_values(
        output_file,
        "path",
        input_path,
        pos=5,
    )
    check_column_values(output_file, "tag_2", "nokey", pos=6)


#   -c CALLBACK, --callback CALLBACK
# pcaptoparquet -c tests/callbacks/01_callback_filter_icmp.py
#       1. "num",
#       2. "utc_date_time",
#       3. "ip_src",
#       4. "ip_dst",
#       5. "transport_type",
#       6. "app_type",
#       7. "app_session",
#       8. "app_seq",
#       9. "app_request",
#      10. "app_response"
def test_basic_input_pcap_one_cb() -> None:
    """
    Run a basic pcap file processing with callback 01_callback_filter_icmp.py.
    """
    one_cb = os.path.join("tests", "callbacks", "01_callback_filter_icmp.py")
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options=f"-f txt -c {one_cb}",
        suffix=SuffixInfo(option="_one_cb"),
    )
    output_file = os.path.join("tests", "out", "99_others", "example_one_cb.txt")
    check_txt_file(output_file, check_col=True, num_lines="17")
    check_column_values(output_file, "transport_type", "ICMP", pos=5)
    check_column_values(output_file, "app_type", "PING", pos=6)


def test_basic_input_pcap_two_cb() -> None:
    """
    Run a basic pcap file processing with two callbacks.
    """
    one_cb = os.path.join("tests", "callbacks", "01_callback_filter_icmp.py")
    two_cb = os.path.join("tests", "callbacks", "02_callback_count_pings.py")
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options=("-f txt " + f"-c '{one_cb}" + f":{two_cb}'"),
        suffix=SuffixInfo(option="_two_cb"),
    )
    output_file = os.path.join("tests", "out", "99_others", "example_two_cb.txt")
    check_txt_file(output_file, check_col=True, num_lines="2")
    check_column_values(output_file, "app_type", "PING", pos=1)
    check_column_values(output_file, "ping_requests", "10", pos=2)


#   -g CONFIG, --config CONFIG
#                         JSON Configuration file for protocol decoding.
def test_basic_input_pcap_config() -> None:
    """
    Run a basic pcap file processing with callback 01_callback_filter_icmp.py.
    """
    cfg_file = os.path.join("tests", "config", "twamplight.cfg")
    run_basic_input(
        out=OutInfo(ext=".txt"),
        options=f"-f txt -g {cfg_file}",
        suffix=SuffixInfo(format="_cfg"),
    )
    output_file = os.path.join("tests", "out", "99_others", "example_cfg.txt")
    check_txt_file(output_file, check_col=True, num_lines="3")
    check_column_values(output_file, "transport_type", "UDP", pos=23)
    check_column_values(output_file, "app_type", "TWAMP", pos=62)


if __name__ == "__main__":

    test_help_message()
    test_basic_input_pcap()
    test_basic_input_pcapng()
    test_mp_input_pcap()
    test_mp_input_pcapng()
    test_stdin_input_pcap()
    test_stdin_input_pcapng()
    test_mp_stdin_input_pcap()
    test_mp_stdin_input_pcapng()
    test_basic_input_pcap_txt()
    test_mp_input_pcap_txt()
    test_basic_input_pcap_json()
    test_mp_input_pcap_json()
    test_basic_input_pcap_p_default()
    test_basic_input_pcap_p_client()
    test_basic_input_pcap_p_network()
    test_basic_input_pcap_p_server()
    test_basic_input_pcap_p_unknown()
    test_basic_input_pcap_p_error()
    test_basic_input_pcap_tag_default()
    test_basic_input_pcap_one_tag()
    test_basic_input_pcap_two_tags()
    test_basic_input_pcap_tag_no_key()
    #    test_basic_input_pcap_tag_overwrite()
    test_basic_input_pcap_one_cb()
    test_basic_input_pcap_two_cb()
    test_basic_input_pcap_config()

    print("All tests passed")
