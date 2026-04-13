import requests
from rich.console import Console
from rich.table import Table

console = Console()
HEADERS_UA = {"User-Agent": "Mozilla/5.0 (compatible; ReconToolkit/2.0)"}

SECURITY_HEADERS = {
    "Content-Security-Policy":    "Prevents XSS — controls allowed content sources",
    "Strict-Transport-Security":  "Forces HTTPS — prevents downgrade attacks",
    "X-Frame-Options":            "Prevents clickjacking via iframe embedding",
    "X-Content-Type-Options":     "Prevents MIME sniffing attacks",
    "Referrer-Policy":            "Controls referrer information leakage",
    "Permissions-Policy":         "Restricts browser feature access (mic, camera, etc.)",
    "X-XSS-Protection":           "Legacy XSS filter for older browsers",
    "Cross-Origin-Opener-Policy": "Isolates browsing context against XS-Leaks",
    "Cross-Origin-Resource-Policy":"Prevents cross-origin reads of resources",
}

INFO_LEAK_HEADERS = [
    "Server", "X-Powered-By", "X-AspNet-Version",
    "X-AspNetMvc-Version", "X-Runtime", "X-Version",
]


def _analyze_cookies(cookies) -> list[str]:
    issues = []
    for c in cookies:
        if not c.secure:
            issues.append(f"[red]'{c.name}'[/red] missing [bold]Secure[/bold] flag")
        if not c.has_nonstandard_attr("HttpOnly"):
            issues.append(f"[red]'{c.name}'[/red] missing [bold]HttpOnly[/bold] flag")
        samesite = c.has_nonstandard_attr("SameSite")
        if not samesite:
            issues.append(f"[yellow]'{c.name}'[/yellow] missing [bold]SameSite[/bold] attribute")
    return issues


def run(domain: str) -> dict:
    """Analyse HTTP security headers, cookies, and information disclosure."""
    console.print(f"\n[bold cyan]HTTP Header Analysis[/bold cyan] → {domain}\n")

    for scheme in ["https", "http"]:
        try:
            r = requests.get(
                f"{scheme}://{domain}", timeout=6,
                headers=HEADERS_UA, allow_redirects=True
            )
            console.print(
                f"[green]Connected via {scheme.upper()}[/green]  "
                f"Status: [bold]{r.status_code}[/bold]  "
                f"Final URL: [dim]{r.url}[/dim]\n"
            )
            break
        except Exception:
            continue
    else:
        console.print("[red]Could not connect.[/red]")
        return {}

    hdrs    = r.headers
    cookies = r.cookies

    # ── Security headers ───────────────────────────────────────────────────────
    present_table = Table(title="✅  Present Security Headers", border_style="green", show_lines=False)
    present_table.add_column("Header",  style="white")
    present_table.add_column("Value",   style="dim", max_width=70, no_wrap=True)

    missing_table = Table(title="❌  Missing Security Headers", border_style="red", show_lines=False)
    missing_table.add_column("Header",  style="white")
    missing_table.add_column("Risk",    style="yellow")

    present, missing = {}, []
    for header, desc in SECURITY_HEADERS.items():
        if header in hdrs:
            present[header] = hdrs[header]
            present_table.add_row(header, hdrs[header])
        else:
            missing.append(header)
            missing_table.add_row(header, desc)

    console.print(present_table)
    console.print()
    console.print(missing_table)

    # Security score
    score = int(len(present) / len(SECURITY_HEADERS) * 100)
    color = "green" if score >= 70 else "yellow" if score >= 40 else "red"
    console.print(f"\n[bold]Security Header Score:[/bold] [{color}]{score}%[/{color}]  "
                  f"({len(present)}/{len(SECURITY_HEADERS)} headers present)")

    # ── Cookies ────────────────────────────────────────────────────────────────
    cookie_issues = _analyze_cookies(cookies)
    if cookie_issues:
        console.print("\n[bold red]🍪  Cookie Issues:[/bold red]")
        for issue in cookie_issues:
            console.print(f"  → {issue}")
    else:
        console.print("\n[green]🍪  No cookie issues detected.[/green]")

    # ── Info leakage ───────────────────────────────────────────────────────────
    leaks = [(h, hdrs[h]) for h in INFO_LEAK_HEADERS if h in hdrs]
    if leaks:
        console.print("\n[bold yellow]⚠   Information Disclosure:[/bold yellow]")
        for h, v in leaks:
            console.print(f"  → [yellow]{h}:[/yellow] {v}")

    console.print()

    return {
        "status_code":       r.status_code,
        "present_headers":   present,
        "missing_headers":   missing,
        "security_score":    score,
        "cookie_issues":     cookie_issues,
        "info_leakage":      {h: hdrs[h] for h in INFO_LEAK_HEADERS if h in hdrs},
    }
