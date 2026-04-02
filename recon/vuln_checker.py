import requests
from rich.console import Console
from rich.table import Table

console = Console()

def check_open_redirect(domain):
    test_url = f"https://{domain}/?url=https://evil.com"
    try:
        r = requests.get(test_url, timeout=5, allow_redirects=False)
        location = r.headers.get("Location", "")
        if "evil.com" in location:
            return True, location
    except Exception:
        pass
    return False, None

def check_reflected_input(domain):
    payload = "<recon-test-xss>"
    test_url = f"https://{domain}/?q={payload}"
    try:
        r = requests.get(test_url, timeout=5)
        if payload in r.text:
            return True
    except Exception:
        pass
    return False

def check_cors(domain):
    headers = {"Origin": "https://evil.com"}
    try:
        r = requests.get(f"https://{domain}", headers=headers, timeout=5)
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        if acao == "*" or "evil.com" in acao:
            return True, acao
    except Exception:
        pass
    return False, None

def check_http_methods(domain):
    dangerous = []
    for method in ["PUT", "DELETE", "TRACE"]:
        try:
            r = requests.request(method, f"https://{domain}", timeout=5)
            if r.status_code not in [404, 405, 501]:
                dangerous.append((method, r.status_code))
        except Exception:
            pass
    return dangerous

def run(domain):
    console.print(f"\n[bold cyan]Running vulnerability checks for:[/bold cyan] {domain}\n")

    table = Table(title="Vulnerability Check Results", border_style="cyan")
    table.add_column("Check", style="white")
    table.add_column("Result", justify="center")
    table.add_column("Detail", style="dim")

    vuln, location = check_open_redirect(domain)
    if vuln:
        table.add_row("Open Redirect", "[bold red]VULNERABLE[/bold red]", f"Redirects to: {location}")
    else:
        table.add_row("Open Redirect", "[green]OK[/green]", "No redirect detected")

    reflected = check_reflected_input(domain)
    if reflected:
        table.add_row("Reflected Input", "[bold red]VULNERABLE[/bold red]", "Input reflected in response — possible XSS")
    else:
        table.add_row("Reflected Input", "[green]OK[/green]", "Input not reflected")

    cors_vuln, acao = check_cors(domain)
    if cors_vuln:
        table.add_row("CORS Misconfiguration", "[bold red]VULNERABLE[/bold red]", f"Allows origin: {acao}")
    else:
        table.add_row("CORS Misconfiguration", "[green]OK[/green]", "No wildcard CORS detected")

    methods = check_http_methods(domain)
    if methods:
        detail = ", ".join([f"{m} ({c})" for m, c in methods])
        table.add_row("Dangerous HTTP Methods", "[yellow]WARNING[/yellow]", detail)
    else:
        table.add_row("Dangerous HTTP Methods", "[green]OK[/green]", "No dangerous methods allowed")

    console.print(table)
    return