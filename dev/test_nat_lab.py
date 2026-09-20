"""Pure runner cleanup tests: no SSH connections or NIC mutations."""
import unittest
from nat_lab import PORTS, pause_command, pause_state, restore_pause


class PauseTests(unittest.TestCase):
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
