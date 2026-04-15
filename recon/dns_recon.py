import dns.resolver
import dns.exception
from rich.console import Console
from rich.table import Table

console = Console()

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _query(domain: str, rtype: str) -> list:
    try:
        return [str(r) for r in dns.resolver.resolve(domain, rtype)]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.exception.Timeout, dns.resolver.NoNameservers):
        return []
    except Exception:
        return []


def run(domain: str) -> dict:
    """Query all DNS record types and analyse email security posture."""
    console.print(f"\n[bold cyan]DNS Reconnaissance[/bold cyan] → {domain}\n")

    results: dict[str, list] = {}

    table = Table(title=f"DNS Records — {domain}", border_style="cyan", show_lines=True)
    table.add_column("Type", style="bold cyan", width=8)
    table.add_column("Records", style="white")

    for rtype in RECORD_TYPES:
        records = _query(domain, rtype)
        results[rtype] = records
        if records:
            table.add_row(rtype, "\n".join(records))

    console.print(table)

    # ── Email security analysis ────────────────────────────────────────────────
    txt_records = results.get("TXT", [])
    spf     = [r for r in txt_records if "v=spf1" in r]
    dmarc   = _query(f"_dmarc.{domain}", "TXT")
    dkim    = _query(f"default._domainkey.{domain}", "TXT")

    console.print("\n[bold cyan]Email Security Analysis:[/bold cyan]")
    _status("SPF",   spf,   "v=spf1 record present",   "Not configured — email spoofing possible")
    _status("DMARC", dmarc, "DMARC record present",     "Not configured — no policy enforcement")
    _status("DKIM",  dkim,  "DKIM key found (default)", "Default selector not found")

    total = sum(len(v) for v in results.values())
    types_found = len([k for k, v in results.items() if v])
    console.print(
        f"\n[bold green]{total} records[/bold green] across "
        f"[cyan]{types_found}[/cyan] record types\n"
    )
    return results


def _status(label: str, records: list, ok_msg: str, fail_msg: str):
    if records:
        console.print(f"  [green]✓ {label}:[/green] {ok_msg}")
    else:
        console.print(f"  [red]✗ {label}:[/red] {fail_msg}")
