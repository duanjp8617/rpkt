"""Pure runner cleanup tests: no SSH connections or NIC mutations."""
import unittest
from unittest.mock import patch
from nat_lab import CASES, PORTS, environment, pause_command, pause_state, profile_time_filter, restore_pause, selected_cases


class PauseTests(unittest.TestCase):
    def test_case_selection_preserves_order_and_rejects_ambiguity(self):
        self.assertEqual(selected_cases(), CASES)
        self.assertEqual(selected_cases(pilot=True), [("udp", 64, 64), ("tcp", 64, 64)])
        self.assertEqual(selected_cases(["tcp:1500:4096", "tcpopts:128:4096"]),
                         [("tcp", 1500, 4096), ("tcpopts", 128, 4096)])
        for names, pilot in [(["udp:64:64"], True), (["udp:64:64"] * 2, False)]:
            with self.assertRaises(AssertionError):
                selected_cases(names, pilot)

    def test_profiles_require_a_valid_active_window(self):
        self.assertEqual(profile_time_filter(["100.0", "105.0"]),
                         " --time 100.250000000,104.750000000")
        for window in [None, [], ["100"], ["100", "101"], ["100", "107"],
                       ["105", "100"], ["nan", "105"]]:
            with self.assertRaises(AssertionError):
                profile_time_filter(window)

    def test_provenance_uses_selected_sources_and_binaries(self):
        with patch("nat_lab.subprocess.check_output", return_value="metadata") as run:
            result = environment("/dut/frozen/release", "/tg/frozen/performance",
                                 "/dut/source", "/tg/source")
        self.assertEqual(result, dict(tg="metadata", duanjp="metadata"))
        commands = {call.args[0][-2]: call.args[0][-1] for call in run.call_args_list}
        self.assertIn("cd /dut/source", commands["duanjp"])
        self.assertIn("sha256sum Cargo.lock", commands["duanjp"])
        self.assertIn("/dut/frozen/release", commands["duanjp"])
        self.assertIn("cd /tg/source", commands["tg"])
        self.assertIn("/tg/frozen/performance", commands["tg"])
        self.assertNotIn("target/performance/examples", " ".join(commands.values()))

    def test_parse_and_command(self):
        output = "Pause parameters for eth0:\nAutonegotiate:\toff\nRX:\ton\nTX:\ton\n"
        state = pause_state(output)
        self.assertEqual(state, dict(autoneg="off", rx="on", tx="on"))
        self.assertEqual(pause_command("eth0", state),
                         "ethtool -A eth0 autoneg off rx on tx on")
        with self.assertRaises(AssertionError):
            pause_state(output.replace("TX:\ton", "TX:\tunknown"))

    def test_all_ports_restored_even_after_failure(self):
        originals = [(h, i, dict(autoneg="off", rx="on", tx="on")) for h, i in PORTS]
        calls = []

        def ssh(host, command, root=False):
            calls.append((host, command, root))
            if command.startswith("ethtool -A"):
                if PORTS[-1][1] in command:
                    raise RuntimeError("simulated write failure")
                return ""
            return "Autonegotiate: off\nRX: on\nTX: on\n"

        errors = restore_pause(ssh, originals)
        self.assertEqual(len(errors), 1)
        writes = [c for c in calls if c[1].startswith("ethtool -A")]
        self.assertEqual(len(writes), 4)
        for (host, command, root), (expected_host, interface, state) in zip(writes, reversed(originals)):
            self.assertEqual((host, command, root),
                             (expected_host, pause_command(interface, state), expected_host == "duanjp"))

    def test_readback_failure_is_reported(self):
        def ssh(host, command, root=False):
            return "Autonegotiate: off\nRX: off\nTX: off\n"
        self.assertEqual(len(restore_pause(ssh, [
            ("tg", "eth0", dict(autoneg="off", rx="on", tx="on"))])), 1)


if __name__ == "__main__":
    unittest.main()
