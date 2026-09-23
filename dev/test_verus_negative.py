#!/usr/bin/env python3
"""Mutation checks: proof failures must be verification failures, not parse errors."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("verus")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    verus = str(Path(shutil.which(args.verus) or args.verus).resolve())
    mutations = [
        ("short fixed-header acceptance", "verification/packet.rs",
         "if buf.chunk_len() < fixed { None }", "if false { None }"),
        ("cursor moves in the wrong direction", "rpkt/src/buffer_math.rs",
         "\n    len - count\n", "\n    len + count\n"),
        ("read one byte beyond validated header", "verification/packet.rs",
         "self.buf.read(offset)", "self.buf.read(offset + 1)"),
        ("write one byte beyond validated header", "verification/packet.rs",
         "self.buf.write(offset, byte)", "self.buf.write(offset + 1, byte)"),
        ("Pbuf fails to rebind a freed boundary segment", "verification/buffers.rs",
         "if must_rebind {", "if false {"),
        ("Pbuf seek selects a segment before the target", "verification/buffers.rs",
         "self.ends[self.current] <= target", "self.ends[self.current] >= target"),
        ("Pbuf constructor leaves an empty leading segment", "verification/buffers.rs",
         "out.seek(0);", "/* missing initial normalization */"),
        ("forged Ethernet range certificate", "verification/generated/ether.rs",
         "field_range(p, 0, 6)", "field_range(p, 0, 15)"),
    ]
    for label, filename, before, after in mutations:
        with tempfile.TemporaryDirectory(prefix="rpkt-verus-negative-") as tmp:
            stage = Path(tmp)
            shutil.copytree(root / "verification", stage / "verification")
            (stage / "rpkt/src").mkdir(parents=True)
            shutil.copy2(root / "rpkt/src/buffer_math.rs", stage / "rpkt/src/buffer_math.rs")
            path = stage / filename
            text = path.read_text()
            assert before in text, f"stale mutation: {label}"
            # Only alter executable/spec text, not an earlier doc comment.
            path.write_text(text.replace(before, after))
            result = subprocess.run([verus, "--no-cheating", "--triggers-mode", "silent",
                                     str(stage / "verification/main.rs")],
                                    capture_output=True, text=True, timeout=180)
            output = result.stdout + result.stderr
            if result.returncode == 0 or not re.search(r"verification results:: .* [1-9]\d* errors?", output):
                raise RuntimeError(f"mutation did not yield a proof failure: {label}\n{output}")
            print(f"rejected: {label}", flush=True)


if __name__ == "__main__":
    main()
