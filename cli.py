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
@click.option("--wordlist-sub", default="wordlists/subdomains.txt")
@click.option("--wordlist-dir", default="wordlists/directories.txt")
@click.option("--output", default=None, help="Save results to a file")
def full(domain, wordlist_sub, wordlist_dir, output):
    """Run the FULL recon pipeline on a DOMAIN."""
    console.print(Panel.fit(
        f"[bold green]Full Recon Pipeline[/bold green] → {domain}\n"
        f"[dim]Running all 4 modules in sequence...[/dim]",
        border_style="green"
    ))
    console.rule("[cyan]Step 1: Subdomain Enumeration[/cyan]")
    subdomains_found = subdomain_module.run(domain, wordlist_sub)
    console.rule("[cyan]Step 2: Directory Discovery[/cyan]")
    directory_module.run(domain, wordlist_dir)
    console.rule("[cyan]Step 3: HTTP Analysis[/cyan]")
    http_analyzer.run(domain)
    console.rule("[cyan]Step 4: Vulnerability Checks[/cyan]")
    vuln_checker.run(domain)
    console.rule("[bold green]Recon Complete[/bold green]")
    console.print(f"\n[bold green]✅ Full recon finished for:[/bold green] {domain}\n")
    if output:
        with open(output, "w") as f:
            f.write(f"Recon Report — {domain}\n")
            f.write("=" * 50 + "\n\n")
            if subdomains_found:
                f.write("Subdomains Found:\n")
                for s in subdomains_found:
                    f.write(f"  - {s}\n")
        console.print(f"[green]Report saved to:[/green] {output}")

if __name__ == "__main__":
    cli()