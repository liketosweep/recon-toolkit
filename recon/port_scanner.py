import asyncio
import socket
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

# Common ports with service names
COMMON_PORTS: dict[int, str] = {
    21:    "FTP",          22:    "SSH",           23:    "Telnet",
    25:    "SMTP",         53:    "DNS",            80:    "HTTP",
    110:   "POP3",         111:   "RPC",            135:   "MSRPC",
    139:   "NetBIOS",      143:   "IMAP",           443:   "HTTPS",
    445:   "SMB",          465:   "SMTPS",          587:   "SMTP",
    993:   "IMAPS",        995:   "POP3S",          1433:  "MSSQL",
    1521:  "Oracle DB",    1723:  "PPTP VPN",       2375:  "Docker (unauth!)",
    2376:  "Docker TLS",   2379:  "etcd",           2380:  "etcd",
    3000:  "Dev Server",   3306:  "MySQL",          3389:  "RDP",
    4443:  "HTTPS-Alt",    5000:  "Dev/Flask",      5432:  "PostgreSQL",
    5900:  "VNC",          5984:  "CouchDB",        6379:  "Redis",
    6443:  "Kubernetes",   7001:  "WebLogic",       8000:  "HTTP-Alt",
    8080:  "HTTP-Alt",     8443:  "HTTPS-Alt",      8888:  "Jupyter/HTTP",
    9000:  "PHP-FPM/SonarQube", 9200: "Elasticsearch", 9300: "Elasticsearch",
    10250: "Kubelet",      11211: "Memcached",      27017: "MongoDB",
    27018: "MongoDB",      28017: "MongoDB Web",    50000: "SAP",
}

# Ports that shouldn't be internet-facing
HIGH_RISK: set[int] = {
    21, 23, 2375, 3306, 3389, 5432, 5900, 5984,
    6379, 7001, 9200, 9300, 10250, 11211, 27017, 27018,
}


async def _probe(host: str, port: int, sem: asyncio.Semaphore, timeout: float) -> tuple[int, bool]:
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, True
        except Exception:
            return port, False


async def _async_scan(host: str, ports: list[int], concurrency: int, timeout: float) -> list[int]:
    sem = asyncio.Semaphore(concurrency)
    tasks = [_probe(host, p, sem, timeout) for p in ports]
    open_ports = []

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                BarColumn(), TaskProgressColumn(), console=console, transient=True) as prog:
        t = prog.add_task(f"[cyan]Scanning {len(tasks)} ports...", total=len(tasks))
        for coro in asyncio.as_completed(tasks):
            port, is_open = await coro
            prog.advance(t)
            if is_open:
                open_ports.append(port)

    return sorted(open_ports)


def run(domain: str, ports: list[int] | None = None,
        concurrency: int = 300, timeout: float = 1.5) -> dict:
    """Async TCP connect scan. Defaults to top common ports."""
    console.print(f"\n[bold cyan]Port Scanner[/bold cyan] → {domain}\n")

    if ports is None:
        ports = list(COMMON_PORTS.keys())

    # Resolve
    try:
        ip = socket.gethostbyname(domain)
        console.print(f"[dim]Resolved:[/dim] {domain} → {ip}")
    except Exception:
        console.print(f"[red]Could not resolve {domain}[/red]")
        return {}

    console.print(f"[dim]Scanning {len(ports)} ports  |  concurrency: {concurrency}  |  timeout: {timeout}s[/dim]\n")

    open_ports = asyncio.run(_async_scan(ip, ports, concurrency, timeout))

    if not open_ports:
        console.print("[yellow]No open ports detected.[/yellow]\n")
        return {"ip": ip, "open_ports": {}}

    table = Table(title=f"Open Ports — {domain}  ({ip})", border_style="cyan", show_lines=False)
    table.add_column("Port",    style="bold cyan", width=8)
    table.add_column("Service", style="white")
    table.add_column("Risk",    style="dim")

    for port in open_ports:
        svc  = COMMON_PORTS.get(port, "Unknown")
        if port in HIGH_RISK:
            risk = "[bold red]HIGH — should not be public[/bold red]"
        elif port in {80, 443, 22, 25, 465, 587, 993, 995}:
            risk = "[green]Expected[/green]"
        else:
            risk = "[yellow]Review[/yellow]"
        table.add_row(str(port), svc, risk)

    console.print(table)
    console.print(
        f"\n[bold green]{len(open_ports)} open ports[/bold green]  "
        f"[red]{len([p for p in open_ports if p in HIGH_RISK])} high-risk[/red]\n"
    )

    return {
        "ip":         ip,
        "open_ports": {str(p): COMMON_PORTS.get(p, "Unknown") for p in open_ports},
    }
