import requests
from rich.console import Console
from rich.table import Table

console = Console()

SECURITY_HEADERS = {
    "Content-Security-Policy": "Prevents XSS attacks by controlling allowed content sources",
    "Strict-Transport-Security": "Forces HTTPS — prevents downgrade attacks",
    "X-Frame-Options": "Prevents clickjacking by blocking iframe embedding",
    "X-Content-Type-Options": "Prevents MIME sniffing attacks",
    "Referrer-Policy": "Controls how much referrer info is shared",
    "Permissions-Policy": "Controls browser features like camera, mic, location",
    "X-XSS-Protection": "Legacy XSS filter for older browsers",
}

def analyze_cookies(cookies):
    issues = []
    for cookie in cookies:
        if not cookie.secure:
            issues.append(f"[red]Cookie '{cookie.name}' missing Secure flag[/red]")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append(f"[red]Cookie '{cookie.name}' missing HttpOnly flag[/red]")
    return issues

def run(domain):
    console.print(f"\n[bold cyan]Analyzing HTTP headers for:[/bold cyan] {domain}\n")
    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=5)
            console.print(f"[green]Connected via {scheme.upper()}[/green] → Status: {r.status_code}\n")
            headers = r.headers
            cookies = r.cookies
            present_table = Table(title="✅ Present Security Headers", border_style="green")
            present_table.add_column("Header", style="white")
            present_table.add_column("Value", style="dim", max_width=60)
            missing_table = Table(title="❌ Missing Security Headers", border_style="red")
            missing_table.add_column("Header", style="white")
            missing_table.add_column("Risk", style="yellow")
            for header, description in SECURITY_HEADERS.items():
                if header in headers:
                    present_table.add_row(header, headers[header])
                else:
                    missing_table.add_row(header, description)
            console.print(present_table)
            console.print()
            console.print(missing_table)
            cookie_issues = analyze_cookies(cookies)
            if cookie_issues:
                console.print("\n[bold red]🍪 Cookie Issues:[/bold red]")
                for issue in cookie_issues:
                    console.print(f"  → {issue}")
            else:
                console.print("\n[green]🍪 No cookie issues found.[/green]")
            info_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
            leaks = [(h, headers[h]) for h in info_headers if h in headers]
            if leaks:
                console.print("\n[bold yellow]⚠️  Information Leakage:[/bold yellow]")
                for h, v in leaks:
                    console.print(f"  → [yellow]{h}:[/yellow] {v}")
            results = {
                "present_headers": {h: headers[h] for h in SECURITY_HEADERS if h in headers},
                "missing_headers": [h for h in SECURITY_HEADERS if h not in headers],
                "cookie_issues": cookie_issues,
                "info_leakage": {h: headers[h] for h in ["Server", "X-Powered-By", "X-AspNet-Version"] if h in headers}
                }
            return results
        except Exception:
            continue
    console.print("[red]Could not connect to the domain.[/red]")