from rich.console import Console
from rich.rule import Rule
from dns_scanner import get_dns_records
from rich.table import Table
import requests
from urllib.parse import urlsplit
from subdomain_scanner import run_subdomain_scan
from http_security import analyze_http
import dns.resolver
import dns.exception


banner = r"""
    ____                        _       ____                     
   / __ \____  ____ ___  ____ _(_)___  / __ \___  _________  ____ 
  / / / / __ \/ __ `__ \/ __ `/ / __ \/ /_/ / _ \/ ___/ __ \/ __ \
 / /_/ / /_/ / / / / / / /_/ / / / / / _, _/  __/ /__/ /_/ / / / /
/_____/\____/_/ /_/ /_/\__,_/_/_/ /_/_/ |_|\___/\___/\____/_/ /_/ 
                  DNS & URL RECONNAISSANCE TOOL
"""

console = Console()

console.print(banner, style='bold green', highlight=False)

console.print(Rule(style='green'))

console.print("[bold green][+] DOMAINRECON INITIALIZED[/bold green]")
console.print("[bold green][+] VERSION: 1.0.0[/bold green]")
console.print()

while True:
    console.print("[bold green]MAIN MENU[/bold green]")
    console.print("[green][1] DNS Scan[/green]")
    console.print("[green][2] URL Check[/green]")
    console.print("[green][3] Subdomain Enumeration[/green]")
    console.print("[green][4] HTTP Security analyzer[/green]")
    console.print("[green][5] Exit[/green]")
    choice = input('Select an option: ')

    if choice == '1':

        domain = input('Enter domain: ').strip()

        table = Table(title=f"DNS Scan: {domain}", style='green')
        table.add_column('Record Type', style='bold green')
        table.add_column('Result', style='green')
        try:
            dns.resolver.resolve(domain, "A")
        except dns.resolver.NXDOMAIN:
            console.print(f'[red]Домен "{domain}" не существует[/red]')
            continue
        except dns.exception.Timeout:
            console.print('[red]Тайм-аут при проверке домена[/red]')
            continue
        table_rows = 0
        for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
            
            records = get_dns_records(domain, record_type)

            if records:
                table_rows += len(records)
                for record in records:
                    table.add_row(record_type, record)
            else:
                table.add_row(record_type, "No records found")

        console.print(f"[bold green][+] Total records: {table_rows}[/bold green]")
        console.print(table)

    elif choice == '2':
        console.print('[bold green]URL Check selected[/bold green]')
        url = input('Enter URL: ')

        try:
            scheme = urlsplit(url).scheme

            if not scheme:
                url = f'https://{url}'

            host = urlsplit(url).hostname

            if not host:
                console.print('[red]!Please, Enter URL[/red]')
                continue
            req = requests.get(f'{url}', timeout=5, allow_redirects=False)
            stat = req.status_code
            color = 'yellow'
            head = req.headers.get('Location')
            fin_url = req.url

            if 200 <= stat <= 299:
                color = 'green'

            elif 300 <= stat <= 399:
                 if head is None:
                    console.print('[red]Redirect URL not provided[/red]')
                 else:
                    console.print(f'[{color}]New-Adress: {head}[/{color}]')
            elif 400 <= stat <= 599:
                color = 'red'
            console.print(f'[{color}]Response Status Code: {stat}\nFinal URL: {fin_url}[/{color}]')

        except requests.exceptions.ConnectionError:
            console.print('[red]!ConnectionError[/red]')

        except requests.exceptions.Timeout:
            console.print(f'[red]!Request Timed Out[/red]')
            
        except requests.exceptions.RequestException as e:
            console.print(f'[red]!Request failed: {e}[/red]')

    elif choice == '3':
        run_subdomain_scan()

    elif choice == '4':
        analyze_http()

    elif choice == '5':
        console.print('[bold green]Exiting DomainRecon...[/bold green]')
        break

    else:
        console.print("[bold green][-] Invalid option[/bold green]")