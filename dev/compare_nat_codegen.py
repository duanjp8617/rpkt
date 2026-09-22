#!/usr/bin/env python3
"""Compare accessor-bearing NAT functions in frozen raw and checked binaries.

Normalization ignores relocation displacements and instruction padding, but
keeps local branch destinations as non-padding instruction indices. This is
an instruction-shape comparison, not a proof of semantic equivalence: RIP-
relative data/call targets are deliberately not compared.
"""
import bisect
import difflib
import hashlib
import re
import subprocess
import sys
from pathlib import Path

SYMBOLS = ["nat_loop::run::<2, nat_loop::kernels::rpkt>", "nat_loop::nat::rpkt_general"]


def instructions(path, symbol):
    symbols = subprocess.check_output(["nm", "-S", "-C", path], text=True).splitlines()
    match = next(line for line in symbols if line.endswith(" t " + symbol))
    start, size = [int(n, 16) for n in match.split()[:2]]
    dump = subprocess.check_output([
        "objdump", "-d", "-C", "--no-show-raw-insn", f"--start-address={start}",
        f"--stop-address={start + size}", path], text=True)
    parsed = []
    for line in dump.splitlines():
        match = re.match(r"\s*([0-9a-f]+):\s*(.*)", line)
        if not match:
            continue
        ins = match[2].split("#")[0].strip()
        if re.search(r"\bnop", ins) or re.fullmatch(r"xchg\s+%ax,%ax", ins):
            continue
        parsed.append((int(match[1], 16), ins))
    addresses = [address for address, _ in parsed]

    def target(match):
        address = int(match[1], 16)
        if start <= address < start + size:
            return f"instruction[{bisect.bisect_left(addresses, address)}]"
        return "<" + match[2] + ">"

    normalized = []
    for _, ins in parsed:
        ins = re.sub(r"-?0x[0-9a-f]+\(%rip\)", "<RIP-relative>", ins)
        normalized.append(re.sub(r"\b([0-9a-f]+) <(.*)>", target, ins))
    return start, size, normalized, dump


def main():
    raw, checked = sys.argv[1:]
    print(__doc__)
    for path in [raw, checked]:
        print(hashlib.sha256(Path(path).read_bytes()).hexdigest(), path)
    for symbol in SYMBOLS:
        a, sa, left, _ = instructions(raw, symbol)
        b, sb, right, _ = instructions(checked, symbol)
        print(f"\n{symbol}\nraw: start={a:#x}, bytes={sa}, non-padding instructions={len(left)}")
        print(f"checked: start={b:#x}, bytes={sb}, non-padding instructions={len(right)}")
        print("\n".join(difflib.unified_diff(left, right, fromfile="raw", tofile="checked", n=3)))


if __name__ == "__main__":
    main()
