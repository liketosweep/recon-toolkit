import asyncio
import aiohttp
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

STATUS_COLORS = {
    200: "[bold green]200[/bold green]",
    201: "[bold green]201[/bold green]",
    301: "[yellow]301[/yellow]",
    302: "[yellow]302[/yellow]",
    307: "[yellow]307[/yellow]",
    403: "[bold red]403[/bold red]",
    401: "[bold red]401[/bold red]",
    500: "[red]500[/red]",
}

NOTES = {
    200: "Accessible",
    201: "Created",
    301: "Redirect",
    302: "Redirect",
    307: "Temp Redirect",
    403: "Forbidden (exists!)",
    401: "Auth required",
    500: "Server error",
}

INTERESTING = {200, 201, 301, 302, 307, 401, 403, 500}
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ReconToolkit/2.0)"}


async def _check(session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore):
    async with sem:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=5),
                allow_redirects=False, ssl=False,
            ) as r:
                return url, r.status
        except Exception:
            return url, None


async def _scan(domain: str, words: list, concurrency: int):
    base = f"https://{domain}"
    sem = asyncio.Semaphore(concurrency)
    found = []

    table = Table(title=f"Discovered Endpoints — {domain}", border_style="cyan", show_lines=False)
    table.add_column("Path", style="white")
    table.add_column("Status", justify="center")
    table.add_column("Note", style="dim")

    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=connector, headers=HEADERS) as session:
        tasks = [_check(session, f"{base}/{w}", sem) for w in words]

        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                      BarColumn(), TaskProgressColumn(), console=console, transient=True) as p:
            t = p.add_task(f"[cyan]Scanning {len(tasks):,} paths...", total=len(tasks))
            for coro in asyncio.as_completed(tasks):
                url, code = await coro
                p.advance(t)
                if code and code in INTERESTING:
                    path = "/" + url.replace(f"{base}/", "")
                    table.add_row(path, STATUS_COLORS.get(code, str(code)), NOTES.get(code, ""))
                    found.append((path.lstrip("/"), code))

    return table, found


def run(domain: str, wordlist_path: str, verbose: bool = False, concurrency: int = 50):
    """Async directory brute-force with progress bar."""
    console.print(f"\n[bold cyan]Directory Discovery[/bold cyan] → {domain}\n")

    try:
        with open(wordlist_path) as f:
            words = [l.strip() for l in f if l.strip()]
    except FileNotFoundError:
        console.print(f"[red]Wordlist not found:[/red] {wordlist_path}")
        return []

    console.print(f"[dim]Wordlist:[/dim] {len(words):,} paths  [dim]Concurrency:[/dim] {concurrency}\n")
    table, found = asyncio.run(_scan(domain, words, concurrency))

    if found:
        console.print(table)
        console.print(f"\n[bold green]Found {len(found)} interesting paths![/bold green]\n")
    else:
        console.print("[yellow]No interesting paths found.[/yellow]")

    return found
