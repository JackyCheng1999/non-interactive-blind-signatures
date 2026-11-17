#!/usr/bin/env bash
set -euo pipefail

# Usage: GMP_PREFIX=... MPFR_PREFIX=... PYTHON=... scripts/build_lazer.sh [checkout]
# Without a checkout, dependencies stay under .deps. No system install is used.
project_dir=$(cd "$(dirname "$0")/.." && pwd)
checkout=${1:-"$project_dir/.deps/lazer"}
revision=10eafeca4cd53ff4fc54193dce904dbd0026fefd
python_cmd=${PYTHON:-python3}
python_cmd=$("$python_cmd" -c 'import sys; print(sys.executable)')
jobs=${JOBS:-4}

if [[ ! -d "$checkout/.git" ]]; then
    git clone https://github.com/lazer-crypto/lazer.git "$checkout"
    git -C "$checkout" checkout --detach "$revision"
fi
checkout=$(cd "$checkout" && pwd)
if [[ $(git -C "$checkout" rev-parse HEAD) != "$revision" ]]; then
    echo "Expected LaZer commit $revision; refusing to change this checkout." >&2
    exit 1
fi

if ! "$python_cmd" -c 'import cffi, setuptools' >/dev/null 2>&1; then
    venv=${LAZER_VENV:-"$project_dir/.deps/lazer-venv"}
    "$python_cmd" -m venv "$venv"
    python_cmd="$venv/bin/python"
    "$python_cmd" -m pip install cffi==2.0.0 pycparser==2.23 setuptools==80.9.0
fi

"$python_cmd" - "$checkout" "$project_dir/third_party/lazer.lock.json" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

checkout, lockfile = map(Path, sys.argv[1:])
lock = json.loads(lockfile.read_text())
for filename, expected in lock["bundled_archives"].items():
    actual = hashlib.sha256((checkout / "third_party" / filename).read_bytes()).hexdigest()
    if actual != expected:
        raise SystemExit("Archive checksum mismatch: " + filename)
patch = lockfile.parent / lock["arm64_patch"]
if hashlib.sha256(patch.read_bytes()).hexdigest() != lock["arm64_patch_sha256"]:
    raise SystemExit("ARM64 patch checksum mismatch")
PY

cd "$checkout"
if [[ ! -d third_party/Falcon-impl-20211101 ]]; then
    unzip -q third_party/Falcon-impl-20211101.zip -d third_party
    patch -d third_party/Falcon-impl-20211101 -p1 < src/falcon.patch
fi
if [[ ! -d third_party/hexl-development ]]; then
    unzip -q third_party/hexl-development.zip -d third_party
fi

if [[ $(uname -s) == Darwin && $(uname -m) == arm64 ]]; then
    patchfile="$project_dir/third_party/lazer-arm64.patch"
    if git apply --check "$patchfile" 2>/dev/null; then
        git apply "$patchfile"
    elif ! git apply --reverse --check "$patchfile" 2>/dev/null; then
        echo "The ARM patch neither applies cleanly nor matches this checkout." >&2
        exit 1
    fi

    gmp_prefix=${GMP_PREFIX:-${CONDA_PREFIX:-}}
    mpfr_prefix=${MPFR_PREFIX:-${CONDA_PREFIX:-}}
    if command -v brew >/dev/null; then
        [[ -n "$gmp_prefix" ]] || gmp_prefix=$(HOMEBREW_NO_AUTO_UPDATE=1 brew --prefix gmp 2>/dev/null || true)
        [[ -n "$mpfr_prefix" ]] || mpfr_prefix=$(HOMEBREW_NO_AUTO_UPDATE=1 brew --prefix mpfr 2>/dev/null || true)
    fi
    if [[ ! -f "$gmp_prefix/include/gmp.h" || ! -f "$mpfr_prefix/include/mpfr.h" ]]; then
        echo "Set GMP_PREFIX and MPFR_PREFIX to existing ARM64 dependency prefixes." >&2
        exit 1
    fi

    # Compile HEXL's existing scalar implementations; cpu_features is x86-only
    # in the bundled version and is unnecessary when AVX dispatch is disabled.
    hexl=third_party/hexl-development/hexl
    "$python_cmd" - "$hexl/include/hexl/util/defines.hpp.in" <<'PY'
from pathlib import Path
import re
import sys

template = Path(sys.argv[1])
text = template.read_text().replace("#cmakedefine HEXL_USE_CLANG", "#define HEXL_USE_CLANG")
text = re.sub(r"#cmakedefine (\w+)", r"/* #undef \1 */", text)
template.with_suffix("").write_text(text)
PY
    mkdir -p native-hexl-build
    native_sources=(
        eltwise/eltwise-mult-mod.cpp eltwise/eltwise-reduce-mod.cpp
        eltwise/eltwise-sub-mod.cpp eltwise/eltwise-add-mod.cpp
        eltwise/eltwise-fma-mod.cpp eltwise/eltwise-cmp-add.cpp
        eltwise/eltwise-cmp-sub-mod.cpp ntt/ntt-internal.cpp
        ntt/ntt-radix-2.cpp ntt/ntt-radix-4.cpp number-theory/number-theory.cpp
    )
    for source in "${native_sources[@]}"; do
        clang++ -std=c++17 -O2 -DNDEBUG -fPIC -I"$hexl" -I"$hexl/include" \
            -c "$hexl/$source" -o "native-hexl-build/$(basename "$source" .cpp).o"
    done
    ar rcs native-hexl-build/libhexl.a native-hexl-build/*.o

    native_cflags="-O2 -Wno-incompatible-pointer-types -I\"$gmp_prefix/include\" -I\"$mpfr_prefix/include\""
    make -j "$jobs" -o third_party/hexl-development -o third_party/Falcon-impl-20211101 \
        liblazer.a src/lazer_shared.o src/hexl_shared.o CFLAGS="$native_cflags"
    clang++ -dynamiclib -Wl,-install_name,@rpath/liblazer.so -o liblazer.so \
        src/lazer_shared.o src/hexl_shared.o third_party/Falcon-impl-20211101/*_static.o \
        native-hexl-build/libhexl.a -L"$gmp_prefix/lib" -L"$mpfr_prefix/lib" \
        -lmpfr -lgmp -lm -Wl,-rpath,"$gmp_prefix/lib" -Wl,-rpath,"$mpfr_prefix/lib"

    export ARCHFLAGS='-arch arm64'
    export MACOSX_DEPLOYMENT_TARGET
    MACOSX_DEPLOYMENT_TARGET=$(sw_vers -productVersion)
    export CFLAGS="$native_cflags"
    export LDFLAGS="-L\"$checkout/native-hexl-build\" -L\"$gmp_prefix/lib\" -L\"$mpfr_prefix/lib\" -Wl,-rpath,\"$checkout\" -Wl,-rpath,\"$gmp_prefix/lib\" -Wl,-rpath,\"$mpfr_prefix/lib\""
elif [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]]; then
    # 'lib' builds LNP and Falcon, without the separate LaBRADOR libraries.
    cmake -S third_party/hexl-development -B third_party/hexl-development/build \
        -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF -DCMAKE_POLICY_VERSION_MINIMUM=3.5
    cmake --build third_party/hexl-development/build -j "$jobs"
    make -j "$jobs" -o third_party/hexl-development -o third_party/Falcon-impl-20211101 lib
else
    echo "Supported builds: Linux x86_64 and Darwin arm64." >&2
    exit 1
fi

cd "$checkout/python"
"$python_cmd" lazer_cffi_build.py "$checkout"
"$python_cmd" -c 'import lazer; print("LaZer import: OK")'

if [[ ${LAZER_SMOKE_TEST:-0} == 1 ]]; then
    cd "$checkout/python/demo"
    "$python_cmd" ../params_cffi_build.py demo_params.h "$checkout"
    "$python_cmd" -u demo.py
fi

printf 'Python: %s\nLaZer module: %s/python\n' "$python_cmd" "$checkout"
