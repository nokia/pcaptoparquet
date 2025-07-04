# Variables
VENV_DIR = venv_build
PYTHON = $(VENV_DIR)/bin/python
PIP = $(VENV_DIR)/bin/pip
BLACK = $(VENV_DIR)/bin/black
ISORT = $(VENV_DIR)/bin/isort
PYRIGHT = $(VENV_DIR)/bin/pyright
FLAKE8 = $(VENV_DIR)/bin/flake8
MYPY = $(VENV_DIR)/bin/mypy
TOX = $(VENV_DIR)/bin/tox
COVERAGE = $(VENV_DIR)/bin/coverage
PYINSTALLER = $(VENV_DIR)/bin/pyinstaller

# Targets
.PHONY: all venv check test coverage build clean clean-venv clean-check clean-test clean-coverage clean-build

all: venv check test build #publish

venv:
	python3 -m venv $(VENV_DIR)
	$(PIP) install --upgrade pip
	$(PIP) install -e .
	$(PIP) install black isort pyright flake8 Flake8-pyproject mypy tox pytest coverage build twine pyinstaller

check: venv
	$(BLACK) --check pcaptoparquet tests pcaptoparquet_cli.py test_cli
	$(ISORT) --check-only pcaptoparquet tests pcaptoparquet_cli.py test_cli
	. $(VENV_DIR)/bin/activate && $(PYRIGHT) pcaptoparquet tests pcaptoparquet_cli.py test_cli
	$(FLAKE8) pcaptoparquet tests pcaptoparquet_cli.py test_cli
	$(MYPY) pcaptoparquet tests pcaptoparquet_cli.py test_cli

fix: venv
	$(BLACK) pcaptoparquet tests pcaptoparquet_cli.py test_cli
	$(ISORT) pcaptoparquet tests pcaptoparquet_cli.py test_cli

test: venv
	$(TOX)

coverage: venv
	. $(VENV_DIR)/bin/activate && $(COVERAGE) run --source=pcaptoparquet --module pytest --verbose tests
	$(COVERAGE) report --show-missing
	$(COVERAGE) html

build: venv
	$(PYTHON) -m build

standalone: venv
	$(PYINSTALLER) --onefile pcaptoparquet_cli.py
	mv dist/pcaptoparquet_cli dist/pcaptoparquet

install: build
	$(PIP) install .

publish: venv
	$(PYTHON) -m twine upload dist/*

clean: clean-venv clean-check clean-test clean-coverage clean-build clean-publish

clean-venv:
	rm -rf $(VENV_DIR)

clean-check:
	find . -name "__pycache__" -exec rm -rf {} +
	find . -name "*.pyc" -exec rm -f {} +
	rm -rf .mypy_cache */.mypy_cache .pytest_cache

clean-test:
	rm -rf .tox
	rm -rf tests/out

clean-coverage:
	rm -rf .coverage htmlcov

clean-build:
	rm -rf build dist *.egg-info

clean-publish:
	rm -rf dist