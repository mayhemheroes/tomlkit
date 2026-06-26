#!/usr/bin/env bash
#
# mayhem/build.sh — build tomlkit's Atheris fuzz harnesses (Python/OSS-Fuzz adaptation).
#
# tomlkit is a PURE-PYTHON project, so we fuzz it with Atheris (libFuzzer-backed). Mayhem requires
# every target's `cmd:` to be an ELF binary, so each harness is frozen into a self-contained ELF with
# PyInstaller --onefile (exactly how OSS-Fuzz's `compile_python_fuzzer` packages a Python target). The
# Atheris wheel ships its own libFuzzer, so the frozen ELF runs as a real libFuzzer target (iterates,
# reports coverage) with no LD_PRELOAD needed for pure-Python code.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image exports the
# build contract ENV (CC/CXX/SANITIZER_FLAGS/DEBUG_FLAGS/LIB_FUZZING_ENGINE/SRC). For a pure-Python
# target the C sanitizer flags don't instrument the fuzzed code (it's Python), but we still:
#   * reference $SANITIZER_FLAGS / $DEBUG_FLAGS (the contract), and
#   * compile a tiny -gdwarf-3 marker object and inject its DWARF<4 debug sections into every frozen
#     harness ELF + standalone reproducer, so Mayhem triage / the DWARF<4 gate are satisfied.
#
# AIR-GAPPED RE-RUN (SPEC §6.5): all Python deps (atheris, pyinstaller, dictgen, pytest, pyyaml) are
# pre-cached into an in-image wheelhouse at $PY_WHEELHOUSE by the Dockerfile (online, once). This script
# installs ONLY from that wheelhouse with `pip install --no-index --find-links` and never reaches PyPI,
# so re-running it offline (the PATCH tier) succeeds. tomlkit itself is (re)installed from the local
# /mayhem source so an agent's PATCH edits are picked up on the re-run.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build contract from the env, with parameter-expansion fallbacks (no if-plumbing).
# SANITIZER_FLAGS uses `=` (kept when explicitly empty); the rest use `:=`.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info, version < 4 (Mayhem triage can't read DWARF >= 4; clang-19's
# plain `-g` emits DWARF-5, so -gdwarf-3 is explicit). Used for the marker object whose debug sections
# are injected into the frozen ELFs below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

# In-image wheelhouse populated by the Dockerfile (offline source of every dependency).
: "${PY_WHEELHOUSE:=/opt/toolchains/python/wheelhouse}"
PIP_OFFLINE=(pip3 install --break-system-packages --no-index --find-links="$PY_WHEELHOUSE")

cd "$SRC"

HARNESSES=(fuzz_parser fuzz_dumps fuzz_toml)

# 1) Install the project (tomlkit) + its fuzzing/test deps from the in-image wheelhouse (offline), into
#    the SYSTEM interpreter. The PyInstaller freeze (step 3) uses the system interpreter, and test.sh's
#    project-owned interpreter copy (step 1b) keeps sys.prefix=/usr so it resolves these same packages.
#    Installing tomlkit from the local source means a PATCH-tier edit to /mayhem/tomlkit is reflected on
#    the re-run. pytest + pyyaml are the test deps (the toml-test known-answer suite imports yaml-free,
#    but pyyaml is kept for parity with upstream's optional test extras).
echo ">> installing tomlkit + fuzzing/test deps from wheelhouse ($PY_WHEELHOUSE) [offline]"
"${PIP_OFFLINE[@]}" atheris pyinstaller dictgen poetry-core pytest pyyaml
# Reinstall tomlkit from local source (offline). --no-build-isolation uses the wheelhouse poetry-core
# build backend (no PyPI); --no-deps because tomlkit has no runtime deps.
"${PIP_OFFLINE[@]}" --no-build-isolation --no-deps --force-reinstall "$SRC"

export PATH="$HOME/.local/bin:$PATH"

# 1b) Project-owned interpreter for test.sh's functional oracle. We COPY the real CPython binary (not a
#     symlink) to a fixed path under $SRC. This matters for the anti-reward-hack sabotage check (§6.3):
#     the verify-repo neuter LD_PRELOADs a shim that _exit(0)s every NON-system executable. The system
#     /usr/bin/python3 is a SPARED path, so driving the suite through it would let a neutered program
#     still "pass" (blind oracle). A COPIED interpreter at $SRC/bin/python3 IS a non-system path → the
#     neuter kills it before any tomlkit code runs → pytest produces no results → test.sh fails, proving
#     the oracle asserts behavior, not exit code. (venv is unusable here: the base image has no
#     ensurepip/python3-venv, and build.sh runs offline as non-root so it can't apt-install it. A bare
#     binary copy keeps sys.prefix=/usr and reuses the system site-packages installed above.)
PYREAL="$(readlink -f "$(command -v python3)")"
mkdir -p "$SRC/bin"
cp "$PYREAL" "$SRC/bin/python3"
chmod +x "$SRC/bin/python3"
"$SRC/bin/python3" -c 'import tomlkit, pytest' >/dev/null

# 2) Compile a tiny DWARF-3 marker object; its debug sections are injected into each frozen ELF so the
#    target carries parseable DWARF < 4 (presence + version are gated by verify-repo §6.2 item 10).
MARKER_DIR="$(mktemp -d)"
printf 'int _mayhem_triage_marker(int x){ return x + 1; }\n' > "$MARKER_DIR/marker.c"
# shellcheck disable=SC2086
$CC $DEBUG_FLAGS -O0 -c "$MARKER_DIR/marker.c" -o "$MARKER_DIR/marker.o"
for s in info abbrev str line; do
  objcopy --dump-section ".debug_$s=$MARKER_DIR/d_$s.bin" "$MARKER_DIR/marker.o" 2>/dev/null || : > "$MARKER_DIR/d_$s.bin"
done
inject_dwarf() {
  local bin="$1"
  objcopy \
    --add-section .debug_info="$MARKER_DIR/d_info.bin"     --set-section-flags .debug_info=readonly,debug \
    --add-section .debug_abbrev="$MARKER_DIR/d_abbrev.bin" --set-section-flags .debug_abbrev=readonly,debug \
    --add-section .debug_str="$MARKER_DIR/d_str.bin"       --set-section-flags .debug_str=readonly,debug \
    --add-section .debug_line="$MARKER_DIR/d_line.bin"     --set-section-flags .debug_line=readonly,debug \
    "$bin" "$bin.dbg"
  mv "$bin.dbg" "$bin"
}

# 3) Freeze each Atheris harness into a self-contained ELF with PyInstaller --onefile, then inject the
#    DWARF marker. PyInstaller is offline (already installed); --paths mayhem lets fuzz_toml import its
#    sibling fuzz_helpers. The frozen ELF is the libFuzzer fuzzer AND (Atheris runs one input file when
#    given a path arg) doubles as the standalone reproducer; we ship a separate `-standalone` copy so the
#    repro artifact + the DWARF gate find it by name.
PYI_WORK="$(mktemp -d)"
for h in "${HARNESSES[@]}"; do
  echo ">> freezing $h -> /mayhem/$h"
  pyinstaller --noconfirm --clean \
    --distpath /mayhem --workpath "$PYI_WORK/$h" --specpath "$PYI_WORK" \
    --onefile --name "$h" \
    --paths "$SRC/mayhem" \
    --hidden-import tomlkit --hidden-import tomlkit.api --hidden-import tomlkit.parser \
    --hidden-import tomlkit.exceptions --hidden-import dictgen \
    "$SRC/mayhem/$h.py"
  inject_dwarf "/mayhem/$h"
  # Standalone (non-fuzzer) reproducer: same frozen target, runs one input file once (Atheris executes a
  # single input when handed a file path). A distinct binary so the repro artifact is discoverable.
  cp "/mayhem/$h" "/mayhem/$h-standalone"
  chmod +x "/mayhem/$h" "/mayhem/$h-standalone"
done

# 4) Tests: tomlkit's suite is pure-Python pytest (no compile step); pytest + pyyaml are already
#    installed from the wheelhouse, and the toml-test submodule is baked into /mayhem/tests/toml-test by
#    the Dockerfile. test.sh only RUNS pytest.

echo ">> build.sh complete: $(ls -1 /mayhem/fuzz_* 2>/dev/null | tr '\n' ' ')"
