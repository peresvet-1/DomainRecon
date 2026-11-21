import requests
from rich.console import Console
from rich.table import Table

console = Console()

def check_security_headers(response):
    security_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Content-Type-Options', 'X-Frame-Options', 'Referrer-Policy']

    missing_headers = []
    warnings = 0
    for header in security_headers:
        if header not in response.headers:
            missing_headers.append(header)

    if 'Content-Security-Policy-Report-Only' in response.headers and 'Content-Security-Policy' not in response.headers:
        warnings += 1
        console.print('[yellow][!] CSP is in Report-Only mode. Policy violations are reported but not enforced.[/yellow]')

    value = response.headers.get('X-Frame-Options')
    values = {'DENY', 'SAMEORIGIN'}
    if value is not None and value.upper() in values:
        console.print('[green][+] X-Frame-Options is configured correctly.[/green]')
    elif value is not None:
        warnings += 1
        console.print('[yellow][!] X-Frame-Options has an unexpected value.[/yellow]')

    x_content_value = response.headers.get('X-Content-Type-Options')
    x_content_values = {'nosniff'}
    if x_content_value is not None and x_content_value.lower() in x_content_values:
        console.print('[green][+] X-Content-Type-Options is configured correctly[/green]')
    elif x_content_value is not None:
        warnings += 1
        console.print('[yellow][!] X-Content-Type-Options has an unexpected value.[/yellow]')
    hsts_value = response.headers.get('Strict-Transport-Security')
    max_age_found = False
    if hsts_value is not None:
        directive = hsts_value.split(';')
        for value in directive:
            check_value = value.strip().startswith('max-age=')
            if check_value:
                max_age_found = True
                max_age = value.split('=')[1]

                try:
                    max_age = int(max_age)
                except ValueError:
                    warnings += 1
                    console.print('[yellow][!] HSTS max-age is not a valid integer.[/yellow]')
                    continue
                
                if max_age > 0:
                    console.print('[green][+] HSTS max-age is configured correctly.[/green]')
                else:
                    warnings += 1
                    console.print('[yellow][!] HSTS max-age is zero or below zero. HSTS protection is effectively disabled.[/yellow]')
        if max_age_found == False:
            warnings += 1
            console.print('[yellow][!] HSTS header is missing the max-age directive.[/yellow]')
    csp_value = response.headers.get('Content-Security-Policy')

    if csp_value is not None and 'unsafe-inline' in csp_value.lower():
        warnings += 1
        console.print('[yellow][!] CSP contains "unsafe-inline", which may weaken protection against XSS attacks.[/yellow]')
    if csp_value is not None and 'unsafe-eval' in csp_value.lower():
        warnings += 1
        console.print('[yellow][!] CSP contains "unsafe-eval", which may weaken protection against XSS attacks.[/yellow]')

    rp_value = response.headers.get('Referrer-Policy')

    valid_policies = {
        'no-referrer',
        'same-origin',
        'strict-origin',
        'strict-origin-when-cross-origin',
        'no-referrer-when-downgrade',
        'origin',
        'origin-when-cross-origin',
        'unsafe-url'
    }

    if rp_value is not None:
        if rp_value == '':
            warnings += 1
            console.print('[yellow][!] Referrer-Policy has an empty value.[/yellow]')
            
        elif rp_value.lower() not in valid_policies:
            warnings += 1
            console.print('[yellow][!] Referrer-Policy has an unexpected value.[/yellow]')

    if missing_headers:
        console.print('[yellow]Missing Headers[/yellow]')
        for header in missing_headers:
            console.print(f'[yellow][-] {header}[/yellow]')

    if not missing_headers and warnings == 0:
        console.print('[green]Headers check successful[/green]')

def analyze_http():
    url = input('Enter URL: ').strip()
    if not url:
        console.print("[red]URL can't be empty[/red]")
        return
    check_https = url.startswith(("https://", "http://"))
    if not check_https:
        url = f'https://{url}'
    try:
        response = requests.get(url, timeout=5)
        console.print(f'[green][+] Status Code: {response.status_code}[/green]')
        console.print(f'[green][+] Final URL: {response.url}[/green]')
    except requests.exceptions.Timeout:
        console.print('[red]Timed Out[/red]')
        return
    except requests.exceptions.RequestException:
        console.print('[red]Request error, try again later[/red]')
        return

    table = Table(title='HTTP Security Headers', style='green')
    table.add_column('Header', style='green')
    table.add_column('Value', style='green')
    for key, value in response.headers.items():
        table.add_row(key, value)
    console.print(table)

    check_security_headers(response)