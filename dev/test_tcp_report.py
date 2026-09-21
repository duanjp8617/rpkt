import unittest

from tcp_report import rate


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


if __name__ == "__main__":
    unittest.main()
