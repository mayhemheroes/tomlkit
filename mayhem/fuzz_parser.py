#!/usr/bin/python3
# OSS-Fuzz harness for tomlkit (ported from google/oss-fuzz projects/tomlkit/fuzz_parser.py).
# Drives tomlkit.parser.Parser on arbitrary unicode input.
import sys
import atheris
import tomlkit


def TestOneInput(data):
    fdp = atheris.FuzzedDataProvider(data)
    parser = tomlkit.parser.Parser(fdp.ConsumeUnicodeNoSurrogates(sys.maxsize))
    try:
        parser.parse()
    except (
        tomlkit.exceptions.TOMLKitError,
        RecursionError,
    ):
        # Recursion errors are not interesting
        pass


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
