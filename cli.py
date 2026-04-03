import click
from rich.console import Console
from rich.panel import Panel
from recon import subdomain as subdomain_module
from recon import directory as directory_module
from recon import http_analyzer 
from recon import vuln_checker
import json

console = Console()

@click.group()
def cli():
    """Recon Toolkit — Automated Web Reconnaissance"""
    pass

def save_json(domain, path, subdomains_found, dirs_found, http_results, vuln_results):
    report = {
        "target": domain,
        "subdomains": subdomains_found,
        "directories": [{"path": f"/{p}", "status": c} for p, c in dirs_found],
        "http_analysis": http_results,
        "vulnerabilities": vuln_results,
    }
    with open(path, "w") as f:
        json.dump(report, f, indent=4)

def save_txt(domain, path, subdomains_found, dirs_found):
    with open(path, "w") as f:
        f.write(f"Recon Report — {domain}\n")
        f.write("=" * 50 + "\n\n")
        f.write("Subdomains Found:\n")
        for s in subdomains_found:
            f.write(f"  - {s}\n")
        f.write("\nDirectories Found:\n")
        for p, c in dirs_found:
            f.write(f"  - /{p} ({c})\n")

@cli.command()
@click.argument("domain")
@click.option("--wordlist", default="wordlists/subdomains.txt", help="Path to subdomain wordlist")
@click.option("--threads", default=10, help="Number of concurrent threads")
def subdomains(domain, wordlist, threads):
    """Enumerate subdomains for a DOMAIN."""
    console.print(Panel.fit(f"[bold cyan]Subdomain Enumeration[/bold cyan] → {domain}", border_style="cyan"))
    subdomain_module.run(domain, wordlist, threads)

@cli.command()
@click.argument("domain")
@click.option("--wordlist", default="wordlists/directories.txt")
@click.option("--verbose", is_flag=True, default=False, help="Show 404s too")
def directories(domain, wordlist, verbose):
    """Brute-force directories on a DOMAIN."""
    console.print(Panel.fit(f"[bold cyan]Directory Discovery[/bold cyan] → {domain}", border_style="cyan"))
    directory_module.run(domain, wordlist, verbose)

@cli.command()
@click.argument("domain")
def analyze(domain):
    """Analyze HTTP headers of a DOMAIN."""
    console.print(Panel.fit(f"[bold cyan]HTTP Analysis[/bold cyan] → {domain}", border_style="cyan"))
    http_analyzer.run(domain)

@cli.command()
@click.argument("domain")
def vulncheck(domain):
    """Run basic vulnerability checks on a DOMAIN."""
    console.print(Panel.fit(f"[bold cyan]Vuln Checker[/bold cyan] → {domain}", border_style="cyan"))
    vuln_checker.run(domain)

@cli.command()
@click.argument("domain")
@click.option("--wordlist-sub", default="wordlists/subdomains.txt")
@click.option("--wordlist-dir", default="wordlists/directories.txt")
@click.option("--output", default=None, help="Save results to a file (.txt or .json)")
@click.option("--threads", default=10, help="Threads for subdomain enumeration")
def full(domain, wordlist_sub, wordlist_dir, output, threads):
    """Run the FULL recon pipeline on a DOMAIN."""
    console.print(Panel.fit(
        f"[bold green]Full Recon Pipeline[/bold green] → {domain}\n"
        f"[dim]Running all 4 modules in sequence...[/dim]",
        border_style="green"
    ))
    console.rule("[cyan]Step 1: Subdomain Enumeration[/cyan]")
    subdomains_found = subdomain_module.run(domain, wordlist_sub, threads) or []
    console.rule("[cyan]Step 2: Directory Discovery[/cyan]")
    dirs_found = directory_module.run(domain, wordlist_dir) or []
    console.rule("[cyan]Step 3: HTTP Analysis[/cyan]")
    http_results = http_analyzer.run(domain) or {}
    console.rule("[cyan]Step 4: Vulnerability Checks[/cyan]")
    vuln_results = vuln_checker.run(domain) or {}
    console.rule("[bold green]Recon Complete[/bold green]")
    console.print(f"\n[bold green]✅ Full recon finished for:[/bold green] {domain}\n")
    if output:
        if output.endswith(".json"):
            save_json(domain, output, subdomains_found, dirs_found, http_results, vuln_results)
        else:
            save_txt(domain, output, subdomains_found, dirs_found)
        console.print(f"[green]Report saved to:[/green] {output}")

if __name__ == "__main__":
    cli()