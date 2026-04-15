import re
import requests
from rich.console import Console
from rich.table import Table

console = Console()
HEADERS = {"User-Agent": "Mozilla/5.0 (compatible; ReconToolkit/2.0)"}

# ── Fingerprint database ───────────────────────────────────────────────────────
# Each entry: tech_name -> list of (type, *args)
#   type "header"  -> (header_name, regex_or_empty)
#   type "body"    -> (regex,)
#   type "cookie"  -> (cookie_name,)
FINGERPRINTS: dict[str, list] = {
    # CMS
    "WordPress":       [("body",   r"wp-content|wp-includes"),
                        ("header", "x-powered-by", r"wordpress")],
    "Drupal":          [("body",   r"Drupal\.settings|drupal\.org"),
                        ("header", "x-generator", r"Drupal")],
    "Joomla":          [("body",   r"/components/com_|Joomla!")],
    "Ghost":           [("body",   r"ghost\.io|content=\"Ghost")],
    "Shopify":         [("body",   r"cdn\.shopify\.com|Shopify\.theme")],
    "Squarespace":     [("body",   r"squarespace\.com|static\.squarespace")],
    "Webflow":         [("body",   r"webflow\.com|data-wf-page")],

    # Backend frameworks
    "Laravel":         [("cookie", "laravel_session")],
    "Django":          [("cookie", "csrftoken")],
    "Ruby on Rails":   [("header", "x-powered-by", r"phusion passenger"),
                        ("cookie", "_session_id")],
    "ASP.NET":         [("header", "x-powered-by", r"asp\.net"),
                        ("header", "x-aspnet-version", r"")],
    "PHP":             [("header", "x-powered-by", r"php")],
    "Node.js/Express": [("header", "x-powered-by", r"express")],
    "Next.js":         [("header", "x-powered-by", r"next\.js"),
                        ("body",   r"__NEXT_DATA__")],
    "Nuxt.js":         [("body",   r"__nuxt|__NUXT__")],

    # JS frameworks
    "React":           [("body",   r"react(?:\.min)?\.js|data-reactroot|__REACT")],
    "Vue.js":          [("body",   r"vue(?:\.min)?\.js|__vue__|v-bind|v-on:")],
    "Angular":         [("body",   r"angular(?:\.min)?\.js|ng-version")],
    "jQuery":          [("body",   r"jquery[.\-][\d.]+(?:\.min)?\.js")],
    "Bootstrap":       [("body",   r"bootstrap(?:\.min)?\.(?:css|js)")],

    # Web servers
    "Nginx":           [("header", "server", r"nginx")],
    "Apache":          [("header", "server", r"apache")],
    "Caddy":           [("header", "server", r"caddy")],
    "LiteSpeed":       [("header", "server", r"litespeed")],

    # CDN / Security
    "Cloudflare":      [("header", "server", r"cloudflare"),
                        ("header", "cf-ray", r"")],
    "Fastly":          [("header", "x-served-by", r"cache"),
                        ("header", "fastly-restarts", r"")],
    "AWS CloudFront":  [("header", "x-amz-cf-id", r"")],
    "Akamai":          [("header", "x-check-cacheable", r""),
                        ("header", "x-akamai-transformed", r"")],
    "Imperva":         [("header", "x-iinfo", r"")],

    # Analytics / Tag Managers
    "Google Analytics":  [("body", r"google-analytics\.com/analytics\.js|gtag\(")],
    "Google Tag Manager":[("body", r"googletagmanager\.com/gtm\.js")],
    "HubSpot":           [("body", r"js\.hs-scripts\.com|hubspot")],
}

CATEGORIES = {
    "WordPress": "CMS",         "Drupal": "CMS",       "Joomla": "CMS",
    "Ghost": "CMS",             "Shopify": "E-Commerce","Squarespace": "Website Builder",
    "Webflow": "Website Builder","Laravel": "Backend",  "Django": "Backend",
    "Ruby on Rails": "Backend", "ASP.NET": "Backend",  "PHP": "Backend",
    "Node.js/Express": "Backend","Next.js": "SSR/Backend","Nuxt.js": "SSR/Backend",
    "React": "JS Framework",    "Vue.js": "JS Framework","Angular": "JS Framework",
    "jQuery": "JS Library",     "Bootstrap": "CSS Framework",
    "Nginx": "Web Server",      "Apache": "Web Server","Caddy": "Web Server",
    "LiteSpeed": "Web Server",  "Cloudflare": "CDN/WAF","Fastly": "CDN",
    "AWS CloudFront": "CDN",    "Akamai": "CDN/WAF",   "Imperva": "WAF",
    "Google Analytics": "Analytics","Google Tag Manager": "Tag Manager","HubSpot": "Marketing",
}


def _detect(response: requests.Response) -> dict[str, str]:
    hdrs   = {k.lower(): v for k, v in response.headers.items()}
    body   = response.text[:60_000]
    cookies = {c.name.lower() for c in response.cookies}
    found  = {}

    for tech, patterns in FINGERPRINTS.items():
        for pat in patterns:
            match = False
            if pat[0] == "body":
                match = bool(re.search(pat[1], body, re.I))
            elif pat[0] == "header":
                hval = hdrs.get(pat[1], "")
                match = bool(hval and (not pat[2] or re.search(pat[2], hval, re.I)))
            elif pat[0] == "cookie":
                match = pat[1] in cookies

            if match:
                # Try to extract a version from the matched header
                version = ""
                if pat[0] == "header" and pat[1] in hdrs:
                    vm = re.search(r"[\d]+(?:\.[\d]+)+", hdrs[pat[1]])
                    version = vm.group() if vm else ""
                found[tech] = version or "detected"
                break

    return found


def run(domain: str) -> dict:
    """Fingerprint technologies via headers, body patterns, and cookies."""
    console.print(f"\n[bold cyan]Technology Detection[/bold cyan] → {domain}\n")

    response = None
    for scheme in ["https", "http"]:
        try:
            response = requests.get(f"{scheme}://{domain}", timeout=8,
                                    allow_redirects=True, headers=HEADERS)
            break
        except Exception:
            continue

    if response is None:
        console.print("[red]Could not connect to target.[/red]")
        return {}

    detected = _detect(response)

    if not detected:
        console.print("[yellow]No technologies fingerprinted.[/yellow]\n")
        return {}

    table = Table(title=f"Tech Stack — {domain}", border_style="cyan", show_lines=False)
    table.add_column("Technology", style="bold white")
    table.add_column("Version",    style="yellow",  width=12)
    table.add_column("Category",  style="dim")

    for tech, version in sorted(detected.items(), key=lambda x: CATEGORIES.get(x[0], "z")):
        cat = CATEGORIES.get(tech, "Other")
        table.add_row(tech, version if version != "detected" else "—", cat)

    console.print(table)
    console.print(f"\n[bold green]{len(detected)} technologies detected[/bold green]\n")
    return detected
