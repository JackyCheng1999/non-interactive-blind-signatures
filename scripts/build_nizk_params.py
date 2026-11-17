"""Build the CFFI module for the checked-in L2 proof parameters."""

import argparse
import os
from pathlib import Path
import platform
import subprocess
import sys


def main():
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lazer-dir", type=Path, default=root / ".deps" / "lazer")
    parser.add_argument("--sage", help="regenerate the header with this Sage executable")
    args = parser.parse_args()
    lazer = args.lazer_dir.resolve()
    header = root / "proofs" / "nibs_l2_params.h"
    if args.sage:
        env = os.environ.copy()
        cache = root / ".deps" / "sage-cache"
        cache.mkdir(parents=True, exist_ok=True)
        env["DOT_SAGE"] = str(cache)
        env["MAXIMA_USERDIR"] = str(cache / "maxima")
        command = [args.sage, "lin-codegen.sage", str(root / "proofs" / "l2_params.py")]
        result = subprocess.run(command, cwd=lazer / "scripts", env=env, capture_output=True, check=True)
        content = b"\n".join(line.rstrip() for line in result.stdout.splitlines()).rstrip()
        header.write_bytes(content + b"\n")
    output = root / ".deps" / "nibs-l2"
    output.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    prefixes = [env.get("GMP_PREFIX"), env.get("MPFR_PREFIX")]
    if platform.system() == "Darwin":
        env["ARCHFLAGS"] = "-arch " + platform.machine()
        prefixes += ["/opt/homebrew/opt/gmp", "/opt/homebrew/opt/mpfr"]
    includes = [str(Path(path) / "include") for path in prefixes if path]
    includes += [env["CPATH"]] if env.get("CPATH") else []
    env["CPATH"] = os.pathsep.join(includes)
    subprocess.run(
        [sys.executable, str(lazer / "python" / "params_cffi_build.py"), str(header), str(lazer)],
        cwd=output,
        env=env,
        check=True,
    )
    print(f"Proof parameter module built in {output}")


if __name__ == "__main__":
    main()
