import importlib
import unittest


class SynapseConfigTests(unittest.TestCase):
    def test_has_http_ports_detects_singles_and_ranges(self):
        if importlib.util.find_spec("yaml") is None:
            self.skipTest("pyyaml not installed in environment")
        synapse = importlib.import_module("synapse")
        self.assertTrue(synapse._has_http_ports("80"))
        self.assertTrue(synapse._has_http_ports("1-1024"))
        self.assertTrue(synapse._has_http_ports("8080"))
        self.assertFalse(synapse._has_http_ports("22,3306,5432"))


if __name__ == "__main__":
    unittest.main()
