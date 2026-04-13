import asyncio
import aiohttp
import dns.resolver
import requests
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from concurrent.futures import ThreadPoolExecutor, as_completed

console = Console()
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ReconToolkit/2.0)"}


# ── Passive sources ────────────────────────────────────────────────────────────

async def _crtsh(session: aiohttp.ClientSession, domain: str) -> set:
    """Certificate Transparency via crt.sh — finds every subdomain issued an SSL cert."""
    found = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=12)) as r:
            if r.status == 200:
                for entry in await r.json(content_type=None):
                    for name in entry.get("name_value", "").split("\n"):
                        name = name.strip().lstrip("*.")
                        if name.endswith(domain) and name != domain:
                            found.add(name)
    except Exception:
        pass
    return found


async def _hackertarget(session: aiohttp.ClientSession, domain: str) -> set:
    """HackerTarget passive DNS — free tier, no key needed."""
    found = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as r:
            if r.status == 200:
                for line in (await r.text()).splitlines():
                    if "," in line:
                        sub = line.split(",")[0].strip()
                        if sub.endswith(domain) and sub != domain:
                            found.add(sub)
    except Exception:
        pass
    return found


async def _passive_enum(domain: str) -> set:
    """Run all passive sources concurrently and merge results."""
    async with aiohttp.ClientSession(headers=HEADERS) as session:
        results = await asyncio.gather(
            _crtsh(session, domain),
            _hackertarget(session, domain),
        )
    merged = set()
    for r in results:
        merged.update(r)
    return merged


# ── Active brute-force ─────────────────────────────────────────────────────────

def _resolve(sub: str) -> bool:
    try:
        dns.resolver.resolve(sub, "A")
        return True
    except Exception:
        return False


def _http_probe(sub: str):
    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{sub}", timeout=3,
                             allow_redirects=False, headers=HEADERS)
            return scheme, r.status_code
        except Exception:
            continue
    return None, None


def _scan_word(word: str, domain: str):
    sub = f"{word}.{domain}"
    if _resolve(sub):
        scheme, code = _http_probe(sub)
        status = "ALIVE" if scheme else "RESOLVED"
        return sub, status, str(code) if code else "-"
    return None


# ── Public entry point ─────────────────────────────────────────────────────────

def run(domain: str, wordlist_path: str, threads: int = 20):
    """
    Enumerate subdomains via:
      1. Passive: crt.sh + HackerTarget (no wordlist needed)
      2. Active: DNS brute-force from wordlist
    """
    console.print(f"\n[bold cyan]Subdomain Enumeration[/bold cyan] → {domain}\n")

    # ── Step 1: passive ────────────────────────────────────────────────────────
    console.print("[dim]Phase 1 — passive enumeration (crt.sh, HackerTarget)...[/dim]")
    passive = asyncio.run(_passive_enum(domain))
    console.print(f"[green]Passive:[/green] {len(passive)} subdomains discovered\n")

    # ── Step 2: brute-force ────────────────────────────────────────────────────
    words = []
    try:
        with open(wordlist_path) as f:
            words = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        console.print(f"[yellow]Wordlist not found:[/yellow] {wordlist_path} — skipping brute-force\n")

    brute: list[str] = []

    table = Table(title=f"Discovered Subdomains — {domain}", border_style="cyan", show_lines=False)
    table.add_column("Subdomain", style="white", no_wrap=True)
    table.add_column("Source", style="dim", width=10)
    table.add_column("Status", style="green")
    table.add_column("HTTP", style="yellow", width=6)

    # Add passive results first (probe HTTP while brute-force runs)
    passive_rows = []
    for sub in sorted(passive):
        scheme, code = _http_probe(sub)
        status = "ALIVE" if scheme else "RESOLVED"
        color = "green" if scheme else "yellow"
        passive_rows.append((sub, f"[{color}]{status}[/{color}]", str(code) if code else "-"))
        table.add_row(sub, "[cyan]passive[/cyan]", f"[{color}]{status}[/{color}]", str(code) if code else "-")

    if words:
        console.print(f"[dim]Phase 2 — brute-forcing {len(words):,} words (threads: {threads})...[/dim]")
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TaskProgressColumn(), console=console, transient=True) as prog:
            t = prog.add_task("[cyan]Brute-forcing...", total=len(words))
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = {ex.submit(_scan_word, w, domain): w for w in words}
                for future in as_completed(futures):
                    prog.advance(t)
                    result = future.result()
                    if result:
                        sub, status, code = result
                        if sub not in passive:
                            color = "green" if status == "ALIVE" else "yellow"
                            table.add_row(sub, "[yellow]brute[/yellow]",
                                          f"[{color}]{status}[/{color}]", code)
                            brute.append(sub)

    all_found = list(passive) + brute

    if all_found:
        console.print(table)
        console.print(
            f"\n[bold green]Total: {len(all_found)} subdomains[/bold green] "
            f"([cyan]{len(passive)} passive[/cyan] + [yellow]{len(brute)} brute[/yellow])\n"
        )
    else:
        console.print("[red]No subdomains found.[/red]")

    return all_found
