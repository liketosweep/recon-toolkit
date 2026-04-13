#!/usr/bin/env python3
import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box

from recon import (
    subdomain as subdomain_mod,
    directory as directory_mod,
    http_analyzer,
    vuln_checker,
    dns_recon,
    ssl_info,
    tech_detect,
    wayback,
    port_scanner,
)
from core import config as cfg_mod, reporter

console = Console()

BANNER = """[bold cyan]
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ████████╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ╚══██╔══╝██║ ██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║       ██║   █████╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║       ██║   ██╔═██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║       ██║   ██║  ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝       ╚═╝   ╚═╝  ╚═╝[/bold cyan]
[dim]  Automated Web Reconnaissance Framework  ·  v2.0.0[/dim]
"""


@click.group(invoke_without_command=True, context_settings={"help_option_names": ["-h", "--help"]})
@click.pass_context
def cli(ctx):
    """Recon Toolkit — Automated web reconnaissance for bug bounty hunters."""
    if ctx.invoked_subcommand is None:
        console.print(BANNER)
        console.print(ctx.get_help())


# ── Individual module commands ────────────────────────────────────────────────

@cli.command()
@click.argument("domain")
@click.option("--wordlist", "-w", default=None, help="Subdomain wordlist path")
@click.option("--threads", "-t", default=None, type=int, help="Brute-force threads")
def subdomains(domain, wordlist, threads):
    """Enumerate subdomains — passive (crt.sh, HackerTarget) + brute-force."""
    cfg = cfg_mod.load()
    subdomain_mod.run(
        domain,
        wordlist or cfg["wordlists"]["subdomains"],
        threads or cfg["threads"],
    )


@cli.command()
@click.argument("domain")
@click.option("--wordlist", "-w", default=None, help="Directory wordlist path")
@click.option("--concurrency", "-c", default=None, type=int, help="Async concurrency")
def directories(domain, wordlist, concurrency):
    """Async directory brute-force — finds accessible/restricted endpoints."""
    cfg = cfg_mod.load()
    directory_mod.run(
        domain,
        wordlist or cfg["wordlists"]["directories"],
        concurrency=concurrency or cfg["concurrency"],
    )


@cli.command()
@click.argument("domain")
def analyze(domain):
    """Analyse HTTP security headers, cookie flags, and info disclosure."""
    http_analyzer.run(domain)


@cli.command()
@click.argument("domain")
def vulncheck(domain):
    """Check for open redirect, CORS, clickjacking, reflected input, and more."""
    vuln_checker.run(domain)


@cli.command()
@click.argument("domain")
def dns(domain):
    """Enumerate DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA) + email security."""
    dns_recon.run(domain)


@cli.command()
@click.argument("domain")
@click.option("--port", "-p", default=443, type=int, help="TLS port (default 443)")
def ssl(domain, port):
    """Inspect the TLS certificate — expiry, SANs, issuer, version."""
    ssl_info.run(domain, port)


@cli.command()
@click.argument("domain")
def tech(domain):
    """Fingerprint the tech stack via headers, body patterns, and cookies."""
    tech_detect.run(domain)


@cli.command()
@click.argument("domain")
@click.option("--limit", "-l", default=300, type=int, help="Max archived URLs to fetch")
def waybackrecon(domain, limit):
    """Mine the Wayback Machine CDX API for archived URLs and hidden endpoints."""
    wayback.run(domain, limit)


@cli.command()
@click.argument("domain")
@click.option("--concurrency", "-c", default=300, type=int, help="Async concurrency")
@click.option("--timeout",     "-t", default=1.5,  type=float, help="Per-port timeout (s)")
def portscan(domain, concurrency, timeout):
    """Async TCP port scanner — checks common ports for exposed services."""
    port_scanner.run(domain, concurrency=concurrency, timeout=timeout)


# ── Full pipeline ─────────────────────────────────────────────────────────────

@cli.command()
@click.argument("domain")
@click.option("--wordlist-sub",  "-ws", default=None, help="Subdomain wordlist")
@click.option("--wordlist-dir",  "-wd", default=None, help="Directory wordlist")
@click.option("--output",        "-o",  default=None, help="Output file (.json / .html / .txt)")
@click.option("--threads",       "-t",  default=None, type=int)
@click.option("--concurrency",   "-c",  default=None, type=int)
@click.option("--skip",          "-s",  multiple=True,
              help="Skip module(s): dns,ssl,tech,wayback,ports,dirs,vulns")
def full(domain, wordlist_sub, wordlist_dir, output, threads, concurrency, skip):
    """
    Run the complete recon pipeline — all 9 modules in sequence.

    \b
    Modules (use --skip to exclude any):
      subdomains, dns, ssl, http, tech, vulns, wayback, ports, dirs
    """
    console.print(BANNER)
    cfg = cfg_mod.load()

    t   = threads     or cfg["threads"]
    c   = concurrency or cfg["concurrency"]
    ws  = wordlist_sub or cfg["wordlists"]["subdomains"]
    wd  = wordlist_dir or cfg["wordlists"]["directories"]
    skip_set = set(skip)

    console.print(Panel.fit(
        f"[bold green]Full Recon Pipeline[/bold green]\n"
        f"[dim]Target:[/dim] [bold]{domain}[/bold]\n"
        f"[dim]Modules skipped:[/dim] {', '.join(skip_set) if skip_set else 'none'}",
        border_style="green",
    ))

    results: dict = {}

    def step(num: int, name: str, key: str, fn, *args, **kwargs):
        if key in skip_set:
            console.rule(f"[dim]Step {num}: {name} — SKIPPED[/dim]")
            return
        console.rule(f"[cyan]Step {num}: {name}[/cyan]")
        results[key] = fn(*args, **kwargs)

    step(1,  "Subdomain Enumeration",  "subdomains",  subdomain_mod.run,  domain, ws, t)
    step(2,  "DNS Recon",              "dns",          dns_recon.run,      domain)
    step(3,  "SSL Certificate",        "ssl",          ssl_info.run,       domain)
    step(4,  "HTTP Header Analysis",   "http",         http_analyzer.run,  domain)
    step(5,  "Technology Detection",   "technologies", tech_detect.run,    domain)
    step(6,  "Vulnerability Checks",   "vulnerabilities", vuln_checker.run, domain)
    step(7,  "Wayback Machine",        "wayback",      wayback.run,        domain)
    step(8,  "Port Scanner",           "open_ports",   port_scanner.run,   domain)
    step(9,  "Directory Discovery",    "directories",  directory_mod.run,  domain, wd, concurrency=c)

    console.rule("[bold green]Recon Complete[/bold green]")
    _print_summary(domain, results)

    if output:
        saved = reporter.save(domain, output, results)
        console.print(f"\n[green]Report saved:[/green] {saved}\n")


def _print_summary(domain: str, results: dict):
    table = Table(title=f"Summary — {domain}", border_style="green",
                  show_lines=False, box=box.SIMPLE)
    table.add_column("Module",   style="bold white")
    table.add_column("Result",   style="green")

    def _count(key, iterable=True):
        v = results.get(key)
        if v is None:
            return "[dim]skipped[/dim]"
        if iterable:
            return f"[cyan]{len(v)}[/cyan] found"
        return "[green]done[/green]"

    table.add_row("Subdomains",    _count("subdomains"))
    table.add_row("DNS Records",   _count("dns", iterable=False) if results.get("dns") else "[dim]skipped[/dim]")
    table.add_row("SSL Info",      "[green]done[/green]" if results.get("ssl") else "[dim]skipped[/dim]")
    table.add_row("HTTP Analysis", "[green]done[/green]" if results.get("http") else "[dim]skipped[/dim]")
    table.add_row("Technologies",  _count("technologies"))
    table.add_row("Directories",   _count("directories"))
    table.add_row("Port Scan",     f"[cyan]{len((results.get('open_ports') or {}).get('open_ports', {}))}[/cyan] open"
                  if results.get("open_ports") else "[dim]skipped[/dim]")
    table.add_row("Wayback URLs",  f"[cyan]{(results.get('wayback') or {}).get('total_urls', 0)}[/cyan] archived"
                  if results.get("wayback") else "[dim]skipped[/dim]")

    vuln_count = 0
    if results.get("vulnerabilities"):
        v = results["vulnerabilities"]
        vuln_count = sum(1 for k in ["open_redirect","reflected_input","cors_misconfiguration","clickjacking"]
                         if v.get(k))
    table.add_row("Vulnerabilities", f"[bold red]{vuln_count} issues[/bold red]"
                  if vuln_count else "[green]0 issues[/green]")

    console.print()
    console.print(table)


if __name__ == "__main__":
    cli()
