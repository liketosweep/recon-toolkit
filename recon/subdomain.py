import dns.resolver
import requests
from rich.console import Console
from rich.table import Table

console = Console() 
def resolve_subdomain(subdomain):
    try:
        dns.resolver.resolve(subdomain, "A")
        return True
    except Exception:
        return False

def check_alive(subdomain):
    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{subdomain}", timeout=3)
            return scheme, r.status_code
        except Exception:
            continue
    return None, None

def run(domain, wordlist_path):
    console.print(f"\n[bold cyan]Starting subdomain enumeration for:[/bold cyan] {domain}\n")
    try:
        with open(wordlist_path) as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]Wordlist not found:[/red] {wordlist_path}")
        return
    found = []
    table = Table(title="Discovered Subdomains", border_style="cyan")
    table.add_column("Subdomain", style="white")
    table.add_column("Status", style="green")
    table.add_column("HTTP Code", style="yellow")
    for word in words:
        subdomain = f"{word}.{domain}"
        console.print(f"[dim]Trying {subdomain}...[/dim]", end="\r")
        if resolve_subdomain(subdomain):
            scheme, code = check_alive(subdomain)
            if scheme:
                status = f"[green]ALIVE[/green]"
                table.add_row(subdomain, status, str(code))
                found.append(subdomain)
            else:
                table.add_row(subdomain, "[yellow]RESOLVED (no HTTP)[/yellow]", "-")
                found.append(subdomain)
    if found:
        console.print(table)
        console.print(f"\n[bold green]Found {len(found)} subdomains![/bold green]")
    else:
        console.print("[red]No subdomains found.[/red]")
    return found