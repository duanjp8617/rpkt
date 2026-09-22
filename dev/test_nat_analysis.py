"""Checks for the analysis tools, without lab hosts or executable fixtures."""
import json
import unittest
from unittest.mock import patch

from compare_nat_codegen import instructions
from summarize_nat_ablation import MODES, summarize


class MatrixTests(unittest.TestCase):
    def setUp(self):
        self.options = dict(perf=False, cases=["udp:64:4096"], repeats=3,
                            dut_binary="raw", baseline_binary="checked")
        self.rows = []
        for mode in MODES:
            for repeat, rate in enumerate([2, 1, 3]):
                self.rows.append(dict(
                    pattern="udp", bytes=64, flows=4096, mode=mode, repeat=repeat,
                    dut_binary="checked" if mode == "rpkt-checked" else "raw",
                    gen=dict(seconds=5),
                    dut=dict(mode="rpkt" if mode == "rpkt-checked" else mode,
                             bad_checksum=0, bad_output=0),
                    sink=dict(rx=rate * 5_000_000, bad_checksum=0, bad_output=0,
                              output_samples=1)))

    def run_summary(self):
        texts = ["\n".join(map(json.dumps, self.rows)),
                 json.dumps(dict(options=self.options))]
        with patch("pathlib.Path.read_text", side_effect=texts):
            return summarize("unused.jsonl")

    def test_median_not_best_run(self):
        result, _ = self.run_summary()
        self.assertEqual(result[0][3]["rpkt"], (2, 1, 3))

    def test_missing_trial_rejected(self):
        self.rows.pop()
        with self.assertRaises(AssertionError):
            self.run_summary()

    def test_duplicate_repeat_rejected(self):
        self.rows[1]["repeat"] = 0
        with self.assertRaises(AssertionError):
            self.run_summary()

    def test_wrong_control_binary_rejected(self):
        self.rows[3]["dut_binary"] = "raw"
        with self.assertRaises(AssertionError):
            self.run_summary()

    def test_instrumented_matrix_rejected(self):
        self.options["perf"] = True
        with self.assertRaises(AssertionError):
            self.run_summary()

    def test_failed_correctness_rejected(self):
        self.rows[0]["sink"]["bad_output"] = 1
        with self.assertRaises(AssertionError):
            self.run_summary()


class CodegenTests(unittest.TestCase):
    def test_local_branch_destination_survives_normalization(self):
        nm = "0000000000001000 0000000000000010 t function\n"
        dump = """
1000: mov 0x12(%rip),%rax # relocation
1007: jmp 100a <function+0xa>
1009: nop
100a: ret
"""
        with patch("subprocess.check_output", side_effect=[nm, dump]):
            address, size, normalized, _ = instructions("unused", "function")
        self.assertEqual((address, size), (0x1000, 16))
        self.assertEqual(normalized, ["mov <RIP-relative>,%rax",
                                      "jmp instruction[2]", "ret"])


if __name__ == "__main__":
    unittest.main()
