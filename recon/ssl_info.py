import ssl
import socket
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table

console = Console()


def _get_cert(domain: str, port: int = 443) -> dict | None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((domain, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                return tls.getpeercert()
    except Exception:
        return None


def _parse(cert: dict) -> dict:
    subject = dict(x[0] for x in cert.get("subject", []))
    issuer  = dict(x[0] for x in cert.get("issuer", []))

    fmt = "%b %d %H:%M:%S %Y %Z"
    not_before = datetime.strptime(cert.get("notBefore", ""), fmt)
    not_after  = datetime.strptime(cert.get("notAfter",  ""), fmt)

    # timezone-naive UTC comparison
    now = datetime.utcnow()
    days_left = (not_after - now).days

    sans = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

    return {
        "subject_cn":   subject.get("commonName", "N/A"),
        "issuer_org":   issuer.get("organizationName", "N/A"),
        "issuer_cn":    issuer.get("commonName", "N/A"),
        "not_before":   not_before.strftime("%Y-%m-%d"),
        "not_after":    not_after.strftime("%Y-%m-%d"),
        "days_left":    days_left,
        "sans":         sans,
        "san_count":    len(sans),
        "version":      cert.get("version", "N/A"),
        "serial":       cert.get("serialNumber", "N/A"),
    }


def run(domain: str, port: int = 443) -> dict:
    """Retrieve and analyse the TLS certificate for a domain."""
    console.print(f"\n[bold cyan]SSL/TLS Certificate Info[/bold cyan] → {domain}:{port}\n")

    cert = _get_cert(domain, port)
    if not cert:
        console.print(f"[red]Could not retrieve TLS certificate from {domain}:{port}[/red]")
        return {}

    info = _parse(cert)

    # ── Expiry badge ───────────────────────────────────────────────────────────
    d = info["days_left"]
    if d < 0:
        expiry = f"[bold red]EXPIRED {abs(d)} days ago[/bold red]"
    elif d < 14:
        expiry = f"[bold red]⚠ Expires in {d} days[/bold red]"
    elif d < 30:
        expiry = f"[bold yellow]⚠ Expires in {d} days — renew soon[/bold yellow]"
    else:
        expiry = f"[green]Valid — {d} days remaining[/green]"

    table = Table(title=f"TLS Certificate — {domain}", border_style="cyan", show_lines=True)
    table.add_column("Field",  style="bold cyan", width=18)
    table.add_column("Value",  style="white")

    table.add_row("Subject CN",   info["subject_cn"])
    table.add_row("Issuer",       f"{info['issuer_org']}  ({info['issuer_cn']})")
    table.add_row("Valid From",   info["not_before"])
    table.add_row("Valid Until",  info["not_after"])
    table.add_row("Expiry",       expiry)
    table.add_row("SANs",         f"{info['san_count']} names")
    table.add_row("Version",      str(info["version"]))

    console.print(table)

    if info["sans"]:
        console.print("\n[bold cyan]Subject Alternative Names (SANs)[/bold cyan]"
                      " [dim]— these often reveal internal / staging hosts[/dim]")
        for san in info["sans"][:25]:
            console.print(f"  [dim]→[/dim] {san}")
        if info["san_count"] > 25:
            console.print(f"  [dim]… and {info['san_count'] - 25} more[/dim]")

    console.print()
    return info
