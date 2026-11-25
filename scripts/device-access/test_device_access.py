import unittest
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from device_access import run_selftest


class DeviceAccessAcceptanceTests(unittest.TestCase):
    def test_three_certificate_combinations_and_disconnect(self):
        self.assertEqual(run_selftest(), 0)


if __name__ == "__main__":
    unittest.main()
