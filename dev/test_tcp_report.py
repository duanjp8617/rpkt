import unittest

from tcp_report import rate, validate_offloads


class TcpReportTests(unittest.TestCase):
    def row(self, mode):
        return {"mode": mode,
                "client": {"responses": 2_000_000, "bytes": 0, "measured_ns": 4_000_000_000,
                           "measured": True, "errors": 0},
                "server": {"responses": 0, "bytes": 3_000_000_000, "measured_ns": 6_000_000_000,
                           "measured": True, "errors": 0}}

    def test_echo_uses_client_actual_interval(self):
        self.assertEqual(rate(self.row("echo")), .5)

    def test_bulk_uses_server_actual_interval(self):
        self.assertEqual(rate(self.row("bulk")), 4.)

    def test_corruption_is_not_a_valid_performance_result(self):
        row = self.row("bulk")
        row["server"]["errors"] = 1
        with self.assertRaises(AssertionError):
            rate(row)

    def offload_row(self):
        row = self.row("bulk")
        row.update(offloads=True, backend="rpkt")
        row["server"].update(offloads=True, chains=10, lro=10, max_rx_len=32000, linearized_bytes=0)
        row["client"].update(offloads=True, tso=10)
        return row

    def test_real_chain_evidence_required(self):
        row = self.offload_row()
        validate_offloads(row)
        row["server"]["chains"] = 0
        with self.assertRaises(AssertionError):
            validate_offloads(row)

    def test_copy_path_evidence_required(self):
        row = self.offload_row()
        row["server"]["linearized_bytes"] = 320000
        with self.assertRaises(AssertionError):
            validate_offloads(row)
        row["linearize_rpkt"] = True
        validate_offloads(row)


if __name__ == "__main__":
    unittest.main()
