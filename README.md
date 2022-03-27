[github_release]: https://img.shields.io/github/release/sdispater/tomlkit.svg?logo=github&logoColor=white
[pypi_version]: https://img.shields.io/pypi/v/tomlkit.svg?logo=python&logoColor=white
[python_versions]: https://img.shields.io/pypi/pyversions/tomlkit.svg?logo=python&logoColor=white
[github_license]: https://img.shields.io/github/license/sdispater/tomlkit.svg?logo=github&logoColor=white
[github_action]: https://github.com/sdispater/tomlkit/actions/workflows/tests.yml/badge.svg

[![GitHub Release][github_release]](https://github.com/sdispater/tomlkit/releases/)
[![PyPI Version][pypi_version]](https://pypi.org/project/tomlkit/)
[![Python Versions][python_versions]](https://pypi.org/project/tomlkit/)
[![License][github_license]](https://github.com/sdispater/tomlkit/blob/master/LICENSE)
<br>
[![Tests][github_action]](https://github.com/sdispater/tomlkit/actions/workflows/tests.yml)

# TOML Kit - Style-preserving TOML library for Python

TOML Kit is a **1.0.0-compliant** [TOML](https://toml.io/) library.

It includes a parser that preserves all comments, indentations, whitespace and internal element ordering,
and makes them accessible and editable via an intuitive API.

You can also create new TOML documents from scratch using the provided helpers.

Part of the implementation has been adapted, improved and fixed from [Molten](https://github.com/LeopoldArkham/Molten).

## Usage

See the [documentation](docs/quickstart.rst) for more information.

## Installation

If you are using [Poetry](https://poetry.eustace.io),
add `tomlkit` to your `pyproject.toml` file by using:

```bash
poetry add tomlkit
```

If not, you can use `pip`:

```bash
pip install tomlkit
```

## Running tests

Please clone the repo with submodules with the following command
`git clone --recurse-submodules https://github.com/sdispater/tomlkit.git`.
We need the submodule - `toml-test` for running the tests.

You can run the tests with `poetry run pytest -q tests`
