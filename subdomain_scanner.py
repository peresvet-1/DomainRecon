import dns.resolver
from rich.console import Console
from rich.table import Table
import re
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress

console = Console()

def load_wordlist(path):
    try:
        with open(path, 'r', encoding='utf-8') as file:
            content = file.readlines()
            subdom = [line.strip() for line in content if line.strip()]
            subdomains = list(dict.fromkeys(subdom))
        return subdomains
    except FileNotFoundError:
        console.print('[red]Wordlist file not found[/red]')
        return []
    except PermissionError:
        console.print('[red]Permission denied: cannot read wordlist[/red]')
        return []

def create_resolver():
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '8.8.8.8']
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    return resolver

def check_dns(subdomain, domain, dns_type, resolver):

    parts = [subdomain, domain]
    url = '.'.join(parts)

    try:

        ips = resolver.resolve(url, dns_type)
        ip_adresses = []

        for ip in ips:
            ip_adresses.append(str(ip))

        if ip_adresses:
            return ip_adresses
        else:
            return []
    
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.LifetimeTimeout,
        dns.resolver.NoNameservers,
     ):
        return []

def get_wildcard_dns(domain, dns_type, resolver):
    wildcard_ips = set()
    
    for _ in range(3):
        fake_sub = uuid.uuid4().hex[:12]
        ips = check_dns(fake_sub, domain, dns_type, resolver)
        if ips:
            wildcard_ips.update(ips)
    return wildcard_ips

    
def run_subdomain_scan():
    domain = input('Enter domain: ').strip()
    if not domain:
        console.print("[red]Domain can't be empty[/red]")
        return
    if '://' in domain or '/' in domain:
        console.print('[red]Enter a domain only, without scheme or path[/red]')
        return

    pattern = r'(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}'

    if not re.fullmatch(pattern, domain):
        console.print('[red]Invalid domain format[/red]')
        return
    dns_type = input('Record Type (A/AAAA): ').strip().upper()

    if dns_type not in ('A', 'AAAA'):
        console.print('[red]Invalid record type[/red]')
        return

    subdomains = load_wordlist('wordlists/subdomains.txt')
    if not subdomains:
        console.print("[red]Wordlist is empty or unavailable[/red]")
        return
    
    result = 0
    results = []
    checked = 0
    resolver = create_resolver()
    wildcard_ips = get_wildcard_dns(domain, dns_type, resolver)
    if wildcard_ips:
        console.print(f"[yellow][!] WildCard DNS detected ({', '.join(wildcard_ips)}), filtering out...[/yellow]")

    with Progress() as progress:
        task = progress.add_task('[green]Scanning subdomains...', total=len(subdomains))
        with ThreadPoolExecutor(max_workers=30) as executor:
            futures = {executor.submit(check_dns, sub, domain, dns_type, resolver): sub for sub in subdomains}

            for future in as_completed(futures):
                sub = futures[future]
                ips = future.result()
                checked += 1
                progress.update(task, advance=1)

                if ips:
                    if wildcard_ips and set(ips).issubset(wildcard_ips):
                        continue
                    result += 1
                    results.append((f'{sub}.{domain}', ips))
    
    if not results:
        console.print('[yellow][!] No subdomains found[/yellow]')
        return
            
    table = Table(title='Subdomain Enumeration', style='green')
    table.add_column('Subdomain', style='green')
    table.add_column('IP Address', style='green')
    table.add_column('IP Count', justify='right', style='green')

    for subdomain, ips in results:
        ips_text = ', '.join(str(ip) for ip in ips)
        table.add_row(subdomain, ips_text, str(len(ips)))

    console.print(table)

    console.print(f'[green][+] Checked Subdomains: {checked}[/green]')
    console.print(f'[green][+] Resolved Subdomains: {result}[/green]')