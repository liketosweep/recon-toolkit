import requests
from rich.console import Console
from rich.table import Table

console = Console()

STATUS_COLORS = {
    200: "[bold green]200[/bold green]",
    301: "[yellow]301[/yellow]",
    302: "[yellow]302[/yellow]",
    403: "[bold red]403[/bold red]",
    401: "[bold red]401[/bold red]",
    500: "[red]500[/red]",
}

def check_path(url):
    try:
        r = requests.get(url, timeout=3, allow_redirects=False)
        return r.status_code
    except Exception:
        return None

def run(domain, wordlist_path):
    console.print(f"\n[bold cyan]Starting directory discovery for:[/bold cyan] {domain}\n")

    try:
        with open(wordlist_path) as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        console.print(f"[red]Wordlist not found:[/red] {wordlist_path}")
        return

    base_url = f"https://{domain}"
    found = []

    table = Table(title="Discovered Endpoints", border_style="cyan")
    table.add_column("Path", style="white")
    table.add_column("Status Code", justify="center")
    table.add_column("Note", style="dim")

    NOTES = {
        200: "Accessible",
        301: "Redirect",
        302: "Redirect",
        403: "Forbidden (exists!)",
        401: "Auth required",
        500: "Server error",
    }

    for word in words:
        url = f"{base_url}/{word}"
        console.print(f"[dim]Trying /{word}...[/dim]", end="\r")
        code = check_path(url)

        if code and code != 404:
            colored_code = STATUS_COLORS.get(code, f"[white]{code}[/white]")
            note = NOTES.get(code, "")
            table.add_row(f"/{word}", colored_code, note)
            found.append((word, code))

    if found:
        console.print(table)
        console.print(f"\n[bold green]Found {len(found)} interesting paths![/bold green]")
    else:
        console.print("[red]No interesting paths found.[/red]")

    return found