import os
import yaml
from pathlib import Path

_DEFAULT: dict = {
    "threads":      20,
    "timeout":      5,
    "concurrency":  50,
    "wordlists": {
        "subdomains":  "wordlists/subdomains.txt",
        "directories": "wordlists/directories.txt",
    },
    "api_keys": {
        "shodan":      "",
        "virustotal":  "",
    },
    "output": {
        "default_format": "json",
        "output_dir":     "reports",
    },
}


def load(path: str = "config.yaml") -> dict:
    """Load config.yaml and deep-merge over defaults."""
    if not os.path.exists(path):
        return _DEFAULT.copy()
    try:
        with open(path) as f:
            user = yaml.safe_load(f) or {}
        cfg = _DEFAULT.copy()
        for k, v in user.items():
            if isinstance(v, dict) and k in cfg and isinstance(cfg[k], dict):
                cfg[k] = {**cfg[k], **v}
            else:
                cfg[k] = v
        return cfg
    except Exception:
        return _DEFAULT.copy()
