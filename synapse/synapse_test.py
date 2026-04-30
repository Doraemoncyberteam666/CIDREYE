import importlib
import unittest
from unittest import mock


class SynapseConfigTests(unittest.TestCase):
    def setUp(self):
        if importlib.util.find_spec("yaml") is None:
            self.skipTest("pyyaml not installed in environment")
        self.synapse = importlib.import_module("synapse")

    def test_has_http_ports_detects_singles_and_ranges(self):
        self.assertTrue(self.synapse._has_http_ports("80"))
        self.assertTrue(self.synapse._has_http_ports("1-1024"))
        self.assertTrue(self.synapse._has_http_ports("8080"))
        self.assertFalse(self.synapse._has_http_ports("22,3306,5432"))

    def test_config_has_nuclei_tags(self):
        self.assertTrue(self.synapse._config_has_nuclei_tags({"nuclei_tags": "cve,rce"}))
        self.assertTrue(self.synapse._config_has_nuclei_tags({"nuclei": {"tags": "xss"}}))
        self.assertFalse(self.synapse._config_has_nuclei_tags({}))


    def test_send_telegram_skips_empty_message(self):
        with mock.patch("synapse.urllib.request.urlopen") as urlopen_mock:
            ok = self.synapse.send_telegram("token", "chat", "   ")
            self.assertTrue(ok)
            urlopen_mock.assert_not_called()

    def test_run_synapse_does_not_append_cve_when_cli_tags_present(self):
        with mock.patch("synapse.subprocess.run") as run_mock, mock.patch("synapse.os.path.exists", return_value=False):
            run_mock.return_value.returncode = 0
            self.synapse.run_synapse("/bin/syn", "127.0.0.1", "80", extra_args=["--nuclei-tags", "rce"])
            cmd = run_mock.call_args[0][0]
            self.assertEqual(cmd.count("--nuclei-tags"), 1)


if __name__ == "__main__":
    unittest.main()
