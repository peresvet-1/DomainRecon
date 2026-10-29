import dns.resolver
from rich.console import Console
from rich.table import Table
import re
from rich.progress import track

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

def check_dns(subdomain, domain, dns_type):

    parts = [subdomain, domain]
    url = '.'.join(parts)

    try:

        ips = dns.resolver.resolve(url, dns_type, lifetime=2)
        ip_adresses = []

        for ip in ips:
            ip_adresses.append(ip)

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

    for subdomain in track(subdomains, description='[green]Scanning subdomains...'):
        success = check_dns(subdomain, domain, dns_type)
        checked += 1

        if success:
            result += 1
            full_list = [subdomain, domain]
            full_name = '.'.join(full_list)
            results.append((full_name, success))
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