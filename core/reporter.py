import json
import os
from datetime import datetime
from pathlib import Path

try:
    from jinja2 import Environment, FileSystemLoader
    _JINJA = True
except ImportError:
    _JINJA = False


def _ensure_dir(path: str):
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)


def save_json(domain: str, path: str, results: dict) -> str:
    _ensure_dir(path)
    report = {
        "tool":       "recon-toolkit",
        "version":    "2.0.0",
        "target":     domain,
        "scan_date":  datetime.now().isoformat(),
        "results":    results,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=4, default=str)
    return path


def save_txt(domain: str, path: str, results: dict) -> str:
    _ensure_dir(path)
    sep = "=" * 60
    with open(path, "w") as f:
        f.write(f"Recon Report — {domain}\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"{sep}\n\n")

        sections = {
            "subdomains":   ("SUBDOMAINS",    lambda v: "\n".join(f"  {s}" for s in v)),
            "directories":  ("DIRECTORIES",   lambda v: "\n".join(f"  /{p}  [{c}]" for p, c in v)),
            "dns":          ("DNS RECORDS",   lambda v: "\n".join(
                                f"  {rtype}: {', '.join(recs)}" for rtype, recs in v.items() if recs)),
            "ssl":          ("SSL CERT",      lambda v: "\n".join(
                                f"  {k}: {val}" for k, val in v.items() if k != "sans")),
            "technologies": ("TECHNOLOGIES",  lambda v: "\n".join(
                                f"  {t}: {ver}" for t, ver in v.items())),
            "open_ports":   ("OPEN PORTS",    lambda v: "\n".join(
                                f"  {p}/tcp — {svc}" for p, svc in (v.get("open_ports") or {}).items())),
            "http":         ("HTTP ANALYSIS", lambda v: (
                                f"  Security Score: {v.get('security_score', 'N/A')}%\n"
                                f"  Missing Headers: {', '.join(v.get('missing_headers', []))}")),
            "vulnerabilities": ("VULNERABILITIES", lambda v: "\n".join(
                                f"  {k}: {'VULNERABLE' if val else 'OK'}"
                                for k, val in v.items() if isinstance(val, bool))),
        }

        for key, (title, fmt) in sections.items():
            if key in results and results[key]:
                f.write(f"{title}\n{'-'*40}\n")
                try:
                    f.write(fmt(results[key]) + "\n\n")
                except Exception:
                    f.write(f"  {results[key]}\n\n")

    return path


def save_html(domain: str, path: str, results: dict) -> str | None:
    if not _JINJA:
        return None
    _ensure_dir(path)

    template_dir = Path(__file__).parent.parent / "templates"
    env = Environment(loader=FileSystemLoader(str(template_dir)), autoescape=True)

    try:
        tpl = env.get_template("report.html")
    except Exception:
        return None

    html = tpl.render(
        domain=domain,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        results=results,
    )
    with open(path, "w") as f:
        f.write(html)
    return path


def save(domain: str, path: str, results: dict) -> str:
    """Auto-dispatch by file extension."""
    if path.endswith(".html"):
        return save_html(domain, path, results) or save_json(domain, path.replace(".html", ".json"), results)
    elif path.endswith(".txt"):
        return save_txt(domain, path, results)
    else:
        if not path.endswith(".json"):
            path += ".json"
        return save_json(domain, path, results)
