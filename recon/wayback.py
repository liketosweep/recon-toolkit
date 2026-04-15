import requests
from rich.console import Console
from rich.table import Table

console = Console()
CDX_URL = "http://web.archive.org/cdx/search/cdx"


def _fetch(domain: str, limit: int = 300) -> list:
    """Query Wayback CDX API — free, no auth."""
    params = {
        "url":      f"*.{domain}/*",
        "output":   "json",
        "fl":       "original,statuscode,mimetype,timestamp",
        "collapse": "urlkey",
        "limit":    limit,
    }
    try:
        r = requests.get(CDX_URL, params=params, timeout=15)
        if r.status_code == 200:
            data = r.json()
            return data[1:] if len(data) > 1 else []  # skip header row
    except Exception:
        pass
    return []


def _categorise(urls: list[str]) -> dict:
    checks = {
        "API endpoints":   lambda u: "/api/" in u.lower() or "/v1/" in u.lower() or "/v2/" in u.lower(),
        "Admin panels":    lambda u: any(x in u.lower() for x in ["/admin", "/dashboard", "/wp-admin", "/backend", "/manage"]),
        "Config files":    lambda u: any(u.lower().endswith(x) for x in [".env", ".config", ".yml", ".yaml", ".xml", ".ini"]),
        "Backup files":    lambda u: any(x in u.lower() for x in [".bak", ".backup", ".old", ".sql", ".dump", ".tar", ".zip"]),
        "JavaScript":      lambda u: u.lower().endswith(".js") and "min.js" not in u.lower(),
        "Login pages":     lambda u: any(x in u.lower() for x in ["/login", "/signin", "/auth", "/register", "/signup"]),
        "Sensitive paths": lambda u: any(x in u.lower() for x in ["/secret", "/private", "/internal", "/debug", "/test", "/dev"]),
    }
    return {cat: [u for u in urls if fn(u)] for cat, fn in checks.items()}


def run(domain: str, limit: int = 300) -> dict:
    """Enumerate archived URLs from the Wayback Machine CDX API."""
    console.print(f"\n[bold cyan]Wayback Machine Recon[/bold cyan] → {domain}\n")
    console.print("[dim]Querying Wayback CDX API (this may take a moment)...[/dim]")

    entries = _fetch(domain, limit)

    if not entries:
        console.print("[red]No archived data found — domain may not be indexed.[/red]\n")
        return {}

    urls       = [e[0] for e in entries]
    statuses   = [e[1] for e in entries]
    mimetypes  = [e[2] for e in entries]

    cats = _categorise(urls)
    interesting_total = sum(len(v) for v in cats.values())

    # ── Summary table ──────────────────────────────────────────────────────────
    summary = Table(title=f"Wayback Archive Summary — {domain}", border_style="cyan")
    summary.add_column("Metric",    style="bold white")
    summary.add_column("Value",     style="yellow", justify="right")

    summary.add_row("Total archived URLs", str(len(urls)))
    summary.add_row("Unique MIME types",   str(len(set(mimetypes))))
    summary.add_row("Interesting URLs",    f"[cyan]{interesting_total}[/cyan]")

    for cat, items in cats.items():
        if items:
            summary.add_row(f"  ↳ {cat}", f"[cyan]{len(items)}[/cyan]")

    console.print(summary)

    # ── Interesting URL breakdown ──────────────────────────────────────────────
    for cat, items in cats.items():
        if items:
            console.print(f"\n[bold cyan]{cat}[/bold cyan] ({len(items)} found)")
            for u in items[:6]:
                console.print(f"  [dim]→[/dim] {u}")
            if len(items) > 6:
                console.print(f"  [dim]… and {len(items) - 6} more[/dim]")

    console.print()
    return {
        "total_urls":  len(urls),
        "urls":        urls,
        "interesting": {k: v for k, v in cats.items() if v},
    }
