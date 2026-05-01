from py_modules import runner


class _OkModule:
    @staticmethod
    def run(ip, port):
        return f"ok:{ip}:{port}"


class _FailingModule:
    @staticmethod
    def run(ip, port):
        raise RuntimeError("unexpected module failure")


def test_run_modules_skips_invalid_results_and_continues_on_module_errors():
    original_registry = dict(runner.MODULE_REGISTRY)
    try:
        runner.MODULE_REGISTRY.clear()
        runner.MODULE_REGISTRY.update({"ok": _OkModule, "bad": _FailingModule})

        findings = runner.run_modules(
            results=[{"ip": "127.0.0.1", "port": 80}, {"ip": None, "port": 22}, {"ip": "10.0.0.1"}],
            enabled_modules={"ok": True, "bad": True},
        )
        assert findings == ["ok:127.0.0.1:80"]
    finally:
        runner.MODULE_REGISTRY.clear()
        runner.MODULE_REGISTRY.update(original_registry)
