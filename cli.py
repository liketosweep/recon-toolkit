import click
from rich.console import Console
from rich.panel import Panel
from recon import subdomain as subdomain_module
from recon import directory as directory_module
from recon import http_analyzer 
from recon import vuln_checker

console = Console()

@click.group()
def cli():
    """Recon Toolkit — Automated Web Reconnaissance"""
    pass

@cli.command()
@click.argument("domain")
@click.option("--wordlist", default="wordlists/subdomains.txt", help="Path to subdomain wordlist")
def subdomains(domain, wordlist):
    """Enumerate subdomains for a DOMAIN."""
    console.print(Panel.fit(f"[bold cyan]Subdomain Enumeration[/bold cyan] → {domain}", border_style="cyan"))
    subdomain_module.run(domain, wordlist)

@cli.command()
@click.argument("domain")
@click.option("--wordlist", default="wordlists/directories.txt", help="Path to directory wordlist")
def directories(domain, wordlist):
    """Brute-force directories on a DOMAIN."""
    console.print(Panel.fit(f"[bold cyan]Directory Discovery[/bold cyan] → {domain}", border_style="cyan"))
    directory_module.run(domain, wordlist)

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
def full(domain):
    """Run the FULL recon pipeline on a DOMAIN."""
    console.print(Panel.fit(f"[bold green]Full Recon Pipeline[/bold green] → {domain}", border_style="green"))
    # Will call all modules in Step 5

if __name__ == "__main__":
    cli()