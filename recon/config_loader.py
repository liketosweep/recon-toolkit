import yaml
import os
from pathlib import Path

DEFAULT_CONFIG = {
    "general": {"threads": 20, "timeout": 5, "user_agent": "ReconToolkit/2.0"},
    "wordlists": {"subdomains": "wordlists/subdomains.txt", "directories": "wordlists/directories.txt"},
    "directory": {"concurrency": 50, "include_redirects": True},
    "ports": {"concurrency": 300, "timeout": 1.5, "scan_mode": "top1000", "custom_ports": []},
    "output": {"directory": "reports", "formats": ["json", "html"]},
    "api_keys": {"shodan": "", "virustotal": "", "securitytrails": ""},
}


def load(path="config.yaml"):
    config = DEFAULT_CONFIG.copy()
    config_path = Path(path)
    if config_path.exists():
        try:
            with open(config_path) as f:
                user_config = yaml.safe_load(f) or {}
            # Deep merge
            for section, values in user_config.items():
                if section in config and isinstance(config[section], dict):
                    config[section].update(values)
                else:
                    config[section] = values
        except Exception as e:
            pass  # Fall back to defaults silently
    return config
