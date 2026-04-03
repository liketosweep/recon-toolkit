import dns.resolver
import requests
from rich.console import Console
from rich.table import Table
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

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

def scan_subdomain(word, domain):
    subdomain = f"{word}.{domain}"
    if resolve_subdomain(subdomain):
        scheme, code = check_alive(subdomain)
        if scheme:
            return (subdomain, "ALIVE", str(code))
        else:
            return (subdomain, "RESOLVED (no HTTP)", "-")
    return None

def run(domain, wordlist_path, threads=10):
    console.print(f"\n[bold cyan]Starting subdomain enumeration for:[/bold cyan] {domain} [dim](threads: {threads})[/dim]\n")
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
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_subdomain, word, domain): word for word in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                subdomain, status, code = result
                color = "green" if status == "ALIVE" else "yellow"
                table.add_row(subdomain, f"[{color}]{status}[/{color}]", code)
                found.append(subdomain)
                console.print(f"[green]Found:[/green] {subdomain}", end="\r")
    if found:
        console.print(table)
        console.print(f"\n[bold green]Found {len(found)} subdomains![/bold green]")
    else:
        console.print("[red]No subdomains found.[/red]")
    return found