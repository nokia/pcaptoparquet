# pcaptoparquet

This is a package for converting pcap files primarily to parquet format. CSV and JSON formats are also supported.

## Installation

To install the package, run the following command:

```sh
pip install pcaptoparquet
```

Or with a virtual environment:

```sh
python -m venv <your_venv>
source <your_venv>/bin/activate   # In windows: .\<your_venv>\Scripts\activate
python -m pip install --upgrade pip
python -m pip install pcaptoparquet
```

## Usage

### Command Line Interface

To see all available options:

```sh
pcaptoparquet -h
```

**Note 1**: Portable executable can be created with pyinstaller but this executable has not been fully tested. Check the Makefile for more information.

**Note 2**: CLI interface was not fully tested in Windows environment. Unit testing is only instrumented for Linux.

**Note 3**: L2TP (v2/v3) and GRE tunnel unwrapping is experimental. GTP-U and VxLAN remain the supported tunnel types. L2TP/GRE is validated with synthetic unit tests, not production BRAS captures; cookie and payload heuristics may miss or mis-label sessions, and the `tunnel` field layout for these types may change.

### MCP server (optional)

The `pcaptoparquet_mcp` extra is a read-only [MCP](https://modelcontextprotocol.io/) Polars engine over a directory of Parquet files this converter already wrote. It does not convert PCAPs.

This is a **breaking change** from both the named-analysis menu and from `query(sql)`. Hosts should call `list_captures` once, then **one** `run`. Wall clock follows MCP round trips (Composer turns), not how many packets were scanned.

It is a guardrail and a query shape, not a faster Polars. If you can run a local script against the Parquet, do that: in-process Polars will almost always win on wall clock. Use the MCP when the host has no shell (or you do not want the model writing Python against a capture directory), when you need a read-only, path-confined engine (stdout is protocol; no PCAP conversion, UDFs, or joins across files), or when the question is schema-shaped (`PACKET_COLUMNS`, SNI caveats, TCP flags as booleans) and the *answer* is a small table (mix, SNI, endpoints, distinct IPs). Token cost can track that table; a million-row scan can stay on the server.

It feels slow when the agent issues many `run`s. Each call is a round trip plus a model turn; the first collect on a large capture is still a Parquet scan with a 30s ceiling (timed-out workers are not cancelled). Peeking at packets, retrying on timeout, or sending twenty plans recreates a long debug loop. `frame_id` only helps after a successful aggregate is already in memory.

- `list_captures` — relative path, size, mtime, and row count (Parquet metadata via Polars).
- `run(capture, plan=…)` — JSON steps (`filter`, `with_columns`, `select`, `unique`, `sort`, `group_by`, `join_packets`, `join`, `from_frame`, `head`) on one relative capture. Expressions include arithmetic (`add`/`sub`/`mul`/`div`; `/0` is null) and `total_ms` (datetime or duration → milliseconds). Named `frames` (max 4) are sibling aggregates from the same input; `join` combines them (`on` or `left_on`+`right_on`). Extra CLI tag columns (`filename`, `path`, and up to 16 others; nested/list/binary skipped) are queryable. `join_packets` attaches a same-capture `group_by`/`unique` back onto packets (not a second file, not a `num` self-join). After `join_packets`, reduce with `unique`/`group_by` so `num` is gone if you need a full distinct list.
- `run(capture, preset=…)` — mix/SNI/samples and tshark-style aggregations: `summarize_capture`, `list_flows`, `sni_table`, `filter_packets`, `tcp_setup`, `app_messages`, `quic_initials`, `endpoints`, `conversations`, `io_stat`. `bytes` columns are `sum(ip_len)` when present. `io_stat` buckets are chronological; `group_limit` drops later time (`truncated`). Top destination ports and counted `app_request` strings are a one-step `plan`, not extra presets:

```json
{"steps": [
  {"op": "group_by", "keys": ["transport_dst_port"],
   "agg": [{"op": "len", "alias": "n"}]},
  {"op": "sort", "by": ["n"], "descending": true}
]}
```

Anything else is one `plan`.

Results are JSON: `columns`, `data`, `truncated`, `returned_rows` (and `plan` when `explain` is true). Success also includes `frame_id` (pass it on a later `run` of the same capture to continue; aggregates stay in memory and are not rescanned). `n_rows` is the collected total when this call was not truncated. Packet-shaped tables (`num` still present) default to a **5-row** preview (`head` to see more, never more than 200). Aggregates and distinct lists (`num` absent) return the full small table, cap 5000 rows and 32KiB. Collect may time out after 30s; the error includes a clipped `explain` plan when available; the worker is not cancelled and must not block the next call.

```sh
pip install 'pcaptoparquet[mcp]'
pcaptoparquet-mcp --parquet-dir /path/to/parquets
```

`make venv` installs the same SDK pin via the `dev` extra. Point an MCP host at `venv_build/bin/pcaptoparquet-mcp` as in [`pcaptoparquet_mcp/mcp.json.example`](pcaptoparquet_mcp/mcp.json.example). The data directory can also be `PCAPTOPARQUET_PARQUET_DIR`.

Stdout is the MCP protocol; logs go to stderr. Tool results (addresses, SNI, DNS, URLs) are sent to the model. Production captures may be unfit for cloud agents. The PyInstaller `make standalone` binary remains converter-only.

### Programming Interface

The `pcaptoparquet` package provides the `E2EPcap` class for converting pcap files to different formats. Here's how you can use it:

1. Import the `E2EPcap` class from the `pcaptoparquet` package:

```python
from pcaptoparquet import E2EPcap
```

2. Create an instance of `E2EPcap` with the path to your pcap file:

```python
pcap = E2EPcap('path_to_your_pcap_file')
```

Replace `'path_to_your_pcap_file'` with the actual path to your pcap file.

3. Use the `export` method of the `E2EPcap` instance to convert the pcap data to a different format:

```python
pcap.export(format='parquet', output='output_directory')
```

The `format` parameter specifies the output format. In this example, we're converting the pcap data to parquet format.

The `output` parameter specifies the directory where the output file will be saved. Replace `'output_directory'` with the actual path to your output directory.

This is a basic example of how to use the `pcaptoparquet` package. Depending on your needs, you might need to use additional methods or parameters.

Refer to `pcaptoparquet_cli.py` for a more complex example of use. In particular, refer to extensibility options such as application protocol implementations and post-processing callbacks associated to E2EConfig class. Full examples included in tests folder (config and callbacks subfolders).

## Contributing

Contributions are welcome. Please follow these steps to contribute:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature-branch`).
3. Make your changes.
4. Run the tests and code quality checks to ensure everything works correctly.
5. Commit your changes (`git commit -am 'Add new feature'`).
6. Push to the branch (`git push origin feature-branch`).
7. Create a new Pull Request.

Please make sure to update tests as appropriate.

If you use Cursor, repository-specific agent guidance lives under `.cursor/` (see `.cursor/README.md`). Those files describe this project's Makefile, tests, and protocol decoder layout only.

### Development Installation

After cloning the repository, you can set up your development environment:

```sh
python -m venv <your_venv>
source <your_venv>/bin/activate   # In windows: .\<your_venv>\Scripts\activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

or

```sh
make venv
```

### Testing

The `pcaptoparquet` package includes a suite of tests to ensure its functionality. These tests are located in the `tests` directory.

To run the tests, you'll need `tox`, which is a tool for automating testing in multiple Python environments.

Here's how you can run the tests:

```bash
tox
```

or

```sh
make test
```

This command will run all the tests in the `tests` directory and display the results in the terminal.

If you make changes to the `pcaptoparquet` code, please make sure to run the tests and ensure they all pass before submitting a pull request.

Coverage is also available but only informational for now:

```sh
make coverage
```

### Code Quality Checks

The `pcaptoparquet` project uses several tools to ensure code quality:

- `black`: for code formatting
- `isort`: for sorting imports
- `pyright`: for type checking
- `ruff`: for linting
- `mypy`: for static type checking

You can run these checks using the following commands:

```sh
black --check pcaptoparquet pcaptoparquet_mcp tests pcaptoparquet_cli.py test_cli
isort --check-only pcaptoparquet pcaptoparquet_mcp tests pcaptoparquet_cli.py test_cli
pyright pcaptoparquet pcaptoparquet_mcp tests pcaptoparquet_cli.py test_cli
ruff check pcaptoparquet pcaptoparquet_mcp tests pcaptoparquet_cli.py test_cli
mypy pcaptoparquet pcaptoparquet_mcp tests pcaptoparquet_cli.py test_cli
```

or

```sh
make check
```

To automatically fix formatting issues:

```sh
make fix
```

## License
This project is licensed under the BSD-3-Clause License. See the `LICENSE` file for more details. Copyright 2025 Nokia.


## DeepWiki
Additional documentation can be found at [pcaptoparquet](https://deepwiki.com/nokia/pcaptoparquet).