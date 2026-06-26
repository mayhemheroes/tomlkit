#!/usr/bin/python3
# OSS-Fuzz harness for tomlkit (ported from google/oss-fuzz projects/tomlkit/fuzz_dumps.py).
# Builds a random nested dict (via dictgen) and round-trips it through tomlkit.api.dumps.
import atheris
import sys
import tomlkit
import dictgen


def test_one_input(input_bytes: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(input_bytes)
    test_data = dictgen.generate(
        max_height=5,
        max_depth=10,
        key_generators=(
            dictgen.random_string,
        ),
        val_generators=(
            dictgen.random_string,
            dictgen.random_bool,
            dictgen.random_int,
            dictgen.random_datetime,
            dictgen.random_float
        ),
        rand_seed=fdp.ConsumeInt(32)
    )
    tomlkit.api.dumps(test_data, sort_keys=fdp.ConsumeBool())


def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
