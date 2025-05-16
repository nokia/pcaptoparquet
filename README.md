# pcaptoparquet

This is a package for converting pcap files primarily to parquet format. CSV and JSON formats are also supported.

## Installation

To install the package, run the following commands:

```sh
python -m venv <your_venv>
source <your_venv>/bin/activate   # In windows: .\<your_venv>\Scripts\activate 
python -m pip install --upgrade pip
python -m pip install -e .
python -m pip install black isort pyright flake8 Flake8-pyproject mypy tox coverage build twine
```

or

```sh
make venv
```

## Usage

### Command line Interface
Just run: 

```sh
pcaptoparquet -h
```

**Note 1**: Portable executable can be created with pyinstaller but this executable has not been fully tested. Just check Makefile for more information.

**Note 2**: CLI interface was not fully tested in windows environment. Unit testing is only intrumented for linux.

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


## Testing

The `pcaptoparquet` package includes a suite of tests to ensure its functionality. These tests are located in the `tests` directory.

To run the tests, you'll need `tox`, which is a tool for automating testing in multiple Python environments.

Here's how you can run the tests with `tox`:

1. If you haven't already, install `tox` with the following command:

```bash
pip install tox
```

2. Navigate to the root directory of the `pcaptoparquet` project.

3. Run the tests with the following command:

```bash
tox
```

or

```sh
make check
```

This command will run all the tests in the `tests` directory and display the results in the terminal.

If you make changes to the `pcaptoparquet` code, please make sure to run the tests and ensure they all pass before submitting a pull request.

Coverage is also available but only informational for now.

## Code Quality Checks

The `pcaptoparquet` project uses several tools to ensure code quality:

- `black`: for code formatting
- `isort`: for sorting imports
- `pyright`: for type checking
- `flake8`: for linting
- `mypy`: for static type checking

You can run these checks using the following commands:

```sh
black --check pcaptoparquet_cli.py pcaptoparquet tests
isort --check-only pcaptoparquet_cli.py pcaptoparquet tests
pyright pcaptoparquet_cli.py pcaptoparquet tests
flake8 pcaptoparquet_cli.py pcaptoparquet tests
mypy pcaptoparquet_cli.py pcaptoparquet tests
```

or

```sh
make check
```


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

## License
This project is licensed under the BSD-3-Clause License. See the `LICENSE` file for more details. Copyright 2025 Nokia.