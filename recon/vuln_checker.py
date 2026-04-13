import requests
from rich.console import Console
from rich.table import Table

console = Console()
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ReconToolkit/2.0)"}


# ── Individual checks ──────────────────────────────────────────────────────────

def check_open_redirect(domain: str) -> tuple[bool, str]:
    payloads = [
        f"https://{domain}/?url=https://evil.com",
        f"https://{domain}/?redirect=https://evil.com",
        f"https://{domain}/?next=https://evil.com",
        f"https://{domain}/?return=https://evil.com",
    ]
    for url in payloads:
        try:
            r = requests.get(url, timeout=5, allow_redirects=False, headers=HEADERS)
            loc = r.headers.get("Location", "")
            if "evil.com" in loc:
                return True, loc
        except Exception:
            pass
    return False, ""


def check_cors(domain: str) -> tuple[bool, str]:
    evil_headers = {"Origin": "https://evil.com", **HEADERS}
    try:
        r = requests.get(f"https://{domain}", headers=evil_headers, timeout=5)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "")
        if acao in ("*",) or "evil.com" in acao:
            vuln_detail = acao
            if acac.lower() == "true":
                vuln_detail += "  [bold red]+ credentials=true (critical)[/bold red]"
            return True, vuln_detail
    except Exception:
        pass
    return False, ""


def check_security_txt(domain: str) -> tuple[bool, str]:
    for path in ["/.well-known/security.txt", "/security.txt"]:
        try:
            r = requests.get(f"https://{domain}{path}", timeout=5, headers=HEADERS)
            if r.status_code == 200 and "contact" in r.text.lower():
                return True, path
        except Exception:
            pass
    return False, ""


def check_http_methods(domain: str) -> list[tuple[str, int]]:
    dangerous = []
    for method in ["PUT", "DELETE", "TRACE", "CONNECT", "PATCH"]:
        try:
            r = requests.request(method, f"https://{domain}", timeout=5, headers=HEADERS)
            if r.status_code not in {404, 405, 501, 403}:
                dangerous.append((method, r.status_code))
        except Exception:
            pass
    return dangerous


def check_clickjacking(domain: str) -> tuple[bool, str]:
    """Domain is vulnerable if it has no X-Frame-Options AND no frame-ancestors CSP."""
    try:
        r = requests.get(f"https://{domain}", timeout=5, headers=HEADERS)
        xfo = r.headers.get("X-Frame-Options", "")
        csp = r.headers.get("Content-Security-Policy", "")
        if not xfo and "frame-ancestors" not in csp:
            return True, "No X-Frame-Options or CSP frame-ancestors"
        return False, xfo or "frame-ancestors in CSP"
    except Exception:
        return False, ""


def check_reflected_input(domain: str) -> tuple[bool, str]:
    """Test multiple reflected-input scenarios."""
    payload = "recon13337xss"
    test_urls = [
        f"https://{domain}/?q={payload}",
        f"https://{domain}/?search={payload}",
        f"https://{domain}/?s={payload}",
    ]
    for url in test_urls:
        try:
            r = requests.get(url, timeout=5, headers=HEADERS)
            if payload in r.text:
                return True, url
        except Exception:
            pass
    return False, ""


# ── Entry point ────────────────────────────────────────────────────────────────

def run(domain: str) -> dict:
    """Run all vulnerability / misconfiguration checks."""
    console.print(f"\n[bold cyan]Vulnerability Checks[/bold cyan] → {domain}\n")

    table = Table(title="Vulnerability Check Results", border_style="cyan", show_lines=True)
    table.add_column("Check",       style="bold white",  width=28)
    table.add_column("Result",      justify="center",    width=18)
    table.add_column("Detail",      style="dim")

    results: dict = {}

    # Open redirect
    vuln, detail = check_open_redirect(domain)
    results["open_redirect"] = vuln
    _row(table, "Open Redirect", vuln, detail or "No redirect detected", warn=True)

    # Reflected input
    vuln, detail = check_reflected_input(domain)
    results["reflected_input"] = vuln
    _row(table, "Reflected Input", vuln, detail or "Input not reflected in response", warn=True)

    # CORS
    vuln, detail = check_cors(domain)
    results["cors_misconfiguration"] = vuln
    _row(table, "CORS Misconfiguration", vuln, detail or "No wildcard CORS detected", warn=True)

    # Clickjacking
    vuln, detail = check_clickjacking(domain)
    results["clickjacking"] = vuln
    _row(table, "Clickjacking", vuln, detail or "X-Frame-Options / CSP present", warn=True)

    # Dangerous methods
    methods = check_http_methods(domain)
    results["dangerous_methods"] = [m for m, _ in methods]
    has_methods = bool(methods)
    detail = ", ".join(f"{m}({c})" for m, c in methods) if methods else "No dangerous methods exposed"
    _row(table, "Dangerous HTTP Methods", has_methods, detail, warn=False)

    # security.txt
    found, path = check_security_txt(domain)
    results["security_txt"] = found
    if found:
        table.add_row("security.txt", "[green]Present[/green]", f"Found at {path}")
    else:
        table.add_row("security.txt", "[yellow]Missing[/yellow]", "No disclosure policy found")

    console.print(table)

    vulns_found = sum([
        results["open_redirect"], results["reflected_input"],
        results["cors_misconfiguration"], results["clickjacking"],
        bool(results["dangerous_methods"]),
    ])
    if vulns_found:
        console.print(f"\n[bold red]{vulns_found} potential issue(s) detected[/bold red]\n")
    else:
        console.print("\n[bold green]No critical issues detected[/bold green]\n")

    return results


def _row(table: Table, name: str, is_vuln: bool, detail: str, warn: bool):
    if is_vuln:
        status = "[bold red]VULNERABLE[/bold red]" if warn else "[yellow]WARNING[/yellow]"
    else:
        status = "[green]OK[/green]"
    table.add_row(name, status, detail)
