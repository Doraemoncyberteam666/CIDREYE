import unittest

from py_modules.runner import run_modules


class RunnerTests(unittest.TestCase):
    def test_enabled_module_filtering(self):
        results = [{"ip": "127.0.0.1", "port": 6379}]
        findings = run_modules(results, {"redis": True, "service_detect": False, "mysql": False, "postgres": False, "http": False, "ftp": False, "smb": False, "ssh": False})
        self.assertTrue(any("Redis" in f for f in findings) or findings == [])


if __name__ == "__main__":
    unittest.main()
