"""Assemble the self-contained installer from the maintained components."""

import argparse
import ast
import os
from pathlib import Path
import re
import stat
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PARTS = (
    "Bootstrap/config.sh",
    "Bootstrap/platform.sh",
    "Core/state.sh",
    "Trust/anchor.sh.in",
    "Trust/repositories.sh",
    "Packages/transactions.sh.in",
    "Updates/preparation.sh.in",
    "Updates/diagnostics.sh.in",
    "Bootstrap/verifier.sh.in",
    "Recovery/reconcile.sh",
    "Recovery/install.sh",
    "Recovery/finalize.sh",
    "Recovery/worker.sh",
    "Bootstrap/main.sh",
)
PAYLOADS = {
    "Trust/vendor-key.asc": "S4_VENDOR_KEY",
    "Packages/admission.py": "PY",
    "Packages/download.py": "PY",
    "Updates/store.py": "PY",
    "Updates/effects.py": "PY",
    "Updates/rpm_test.py": "PY",
    "Updates/capacity.py": "PY",
    "Updates/interpreters.py": "PY",
    "Updates/removals.py": "PY",
    "Updates/plan.py": "PY",
    "Updates/sandbox.py": "PY",
    "Bootstrap/integrity.py": "PY",
    "Bootstrap/participation.py": "PY",
}
INPUTS = (*PARTS, *PAYLOADS)
INCLUDE = re.compile(rb"# @s4-include ([A-Za-z0-9_./-]+)\n")
TARGET = "azurelinux3s4.sh"


def read_source(root, relative):
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise ValueError("assembly input must be a regular file: " + relative)
    data = path.read_bytes()
    data.decode("utf-8")
    if not data.endswith(b"\n") or b"\r" in data or b"\0" in data:
        raise ValueError("assembly input must use UTF-8, LF and a final newline: " + relative)
    return data


def assemble(root=ROOT):
    used = set()
    pieces = []
    for index, relative in enumerate(PARTS):
        for line in read_source(root, relative).splitlines(keepends=True):
            match = INCLUDE.fullmatch(line)
            if not match:
                if b"@s4-include" in line:
                    raise ValueError("malformed assembly directive in " + relative)
                pieces.append(line)
                continue
            payload = match[1].decode("ascii")
            if payload not in PAYLOADS or payload in used:
                raise ValueError("unknown or repeated assembly payload: " + payload)
            data = read_source(root, payload)
            if (PAYLOADS[payload].encode() in data.splitlines()
                    or b"@s4-include" in data):
                raise ValueError("payload collides with its assembly boundary: " + payload)
            if payload.endswith(".py"):
                ast.parse(data, filename=payload)
            pieces.append(data)
            used.add(payload)
        if index + 1 < len(PARTS):
            pieces.append(b"\n")
    if used != PAYLOADS.keys():
        raise ValueError("assembly is missing declared payloads: " + ", ".join(sorted(PAYLOADS.keys() - used)))
    return b"".join(pieces)


def target_path(root):
    path = root / TARGET
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise ValueError("installer target must be a regular file")
    return path


def publish(root, data):
    target = target_path(root)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix=".azurelinux3s4-", suffix=".tmp",
                                         dir=root, delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fchmod(stream.fileno(), 0o755)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="refuse if the installer differs from its maintained sources")
    args = parser.parse_args()
    try:
        data = assemble()
        target = target_path(ROOT)
        if args.check:
            if (not target.is_file() or target.read_bytes() != data
                    or stat.S_IMODE(target.stat().st_mode) != 0o755):
                parser.exit(1, "azurelinux3s4.sh differs from its sources or mode; run Bootstrap/pack.py\n")
        else:
            publish(ROOT, data)
    except (OSError, ValueError, SyntaxError) as error:
        parser.exit(1, "Installer assembly failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
