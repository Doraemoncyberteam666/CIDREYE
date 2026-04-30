from . import ftp_module, service_detect_module, smb_module, ssh_module

MODULE_REGISTRY = {
    "ftp": ftp_module,
    "smb": smb_module,
    "ssh": ssh_module,
    "service_detect": service_detect_module,
}

def run_modules(results, enabled_modules):
    findings = []
    modules = [MODULE_REGISTRY[name] for name, enabled in enabled_modules.items() if enabled and name in MODULE_REGISTRY]

    for res in results:
        ip = res.get("ip")
        port = res.get("port")
        for module in modules:
            finding = module.run(ip, port)
            if finding:
                findings.append(finding)
                print(finding)
    return findings
